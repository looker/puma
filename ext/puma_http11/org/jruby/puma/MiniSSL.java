package org.jruby.puma;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;

import org.jruby.anno.JRubyMethod;

import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

import org.jruby.util.ByteList;


import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.*;
import java.io.*;
import java.security.*;
import java.nio.*;
import java.security.cert.CertificateException;

/**
 * dm todo synchronization concerns?
 */
public class MiniSSL extends RubyObject {
  private static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
    public IRubyObject allocate(Ruby runtime, RubyClass klass) {
      return new MiniSSL(runtime, klass);
    }
  };

  public static void createMiniSSL(Ruby runtime) {
    RubyModule mPuma = runtime.defineModule("Puma");
    RubyModule ssl =   mPuma.defineModuleUnder("MiniSSL");

    mPuma.defineClassUnder("SSLError",
                           runtime.getClass("IOError"),
                           runtime.getClass("IOError").getAllocator());

    RubyClass eng = ssl.defineClassUnder("Engine",runtime.getObject(),ALLOCATOR);
    eng.defineAnnotatedMethods(MiniSSL.class);
  }

  private SSLEngine  engine;

  /**
   * dm todo doc
   * dm todo this is mostly pass throughs to ByteBuffer.  Do we need a better abstraction?
   */
  private static class MiniSSLBuffer {
    ByteBuffer buffer;

    private MiniSSLBuffer(int capacity) {
      buffer = ByteBuffer.allocate(capacity);
      buffer.limit(0);
      buffer.clear();
    }

    public void put(byte[] bytes) {
      buffer.limit(buffer.limit() + bytes.length);
      buffer.put(bytes);
    }

    public ByteBuffer getRawBuffer() {
      return buffer;
    }

    public void clear() {
      buffer.clear();
    }

    public void flip() {
      buffer.flip();
    }

    public boolean hasRemaining() {
      return buffer.hasRemaining();
    }

    public int position() {
      return buffer.position();
    }

    public int capacity() {
      return buffer.capacity();
    }

    public void resize(int newCapacity) {
      ByteBuffer dstTmp = ByteBuffer.allocate(newCapacity + buffer.position());
      buffer.flip();
      dstTmp.put(buffer);
      buffer = dstTmp;
    }

    // dm todo doc that this drains the buffer?
    public ByteList asByteList() {
      buffer.flip();
      if (!buffer.hasRemaining()) {
        buffer.clear();
        return null;
      }

      byte[] bss = new byte[buffer.limit()];

      buffer.get(bss);
      buffer.clear();
      return new ByteList(bss);
    }
  }

  private MiniSSLBuffer appData;
  private MiniSSLBuffer inboundNetData;
  private MiniSSLBuffer outboundNetData;

  public MiniSSL(Ruby runtime, RubyClass klass) {
    super(runtime, klass);
  }

  @JRubyMethod(meta = true)
  public static IRubyObject server(ThreadContext context, IRubyObject recv, IRubyObject key, IRubyObject cert) {
      RubyClass klass = (RubyClass) recv;

      return klass.newInstance(context,
          new IRubyObject[] { key, cert },
          Block.NULL_BLOCK);
  }

  @JRubyMethod
  public IRubyObject initialize(IRubyObject key, IRubyObject cert)
      throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {
    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
    KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());

    // dm todo this is the test password
    char[] pass = "blahblah".toCharArray();

    ks.load(new FileInputStream(key.convertToString().asJavaString()),
                                pass);
    ts.load(new FileInputStream(cert.convertToString().asJavaString()),
            pass);

    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
    kmf.init(ks, pass);

    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
    tmf.init(ts);

    SSLContext sslCtx = SSLContext.getInstance("TLS");

    sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

    engine = sslCtx.createSSLEngine();
    engine.setUseClientMode(false);
    // engine.setNeedClientAuth(true);

    SSLSession session = engine.getSession();
    inboundNetData = new MiniSSLBuffer(session.getPacketBufferSize());
    outboundNetData = new MiniSSLBuffer(session.getPacketBufferSize());
    appData = new MiniSSLBuffer(session.getApplicationBufferSize());

    return this;
  }

  @JRubyMethod
  public IRubyObject inject(IRubyObject arg) {
    byte[] bytes = arg.convertToString().getBytes();

    inboundNetData.put(bytes);

    log("inboundNetData injected: " + bytes.length + " bytes");
    return this;
  }

  private abstract class SSLOp {
    MiniSSLBuffer src;
    MiniSSLBuffer dst;

    protected SSLOp(MiniSSLBuffer src, MiniSSLBuffer dst) {
      this.src = src;
      this.dst = dst;
    }

    // dm todo doc
    abstract SSLEngineResult run(ByteBuffer src, ByteBuffer dst) throws SSLException;

    // dm todo doc
    final SSLEngineResult doRun()  throws SSLException {
      SSLEngineResult res = null;
      boolean retryOp = true;
      while (retryOp) {
        res = run(src.getRawBuffer(), dst.getRawBuffer());
        switch (res.getStatus()) {
          case BUFFER_OVERFLOW:
            log("Overflowin'");
            // Could attempt to drain the dst buffer of any already obtained
            // data, but we'll just increase it to the size needed.
            int newSize = Math.max(engine.getSession().getPacketBufferSize(), engine.getSession().getApplicationBufferSize());
            dst.resize(newSize);
            // retry the operation.
            retryOp = true;
            break;
          case BUFFER_UNDERFLOW:
            log("Underflowin'");
            newSize = Math.max(engine.getSession().getPacketBufferSize(), engine.getSession().getApplicationBufferSize());
            // Resize buffer if needed.
            if (newSize > dst.capacity()) {
              src.resize(newSize);
            }
            // need to wait for more data to come in before we retry
            retryOp = false;
            break;
          default:
            retryOp = false;
            // dm todo other cases: CLOSED, OK.
        }
      }

      runDelegatedTasks(engine.getHandshakeStatus(), engine);
      log("AFTER OP -> read: ", engine, res);
      return res;
    }
  }

  @JRubyMethod
  public IRubyObject read() throws Exception {
    log("about to read inboundNetData bytes: " + inboundNetData.position());
    inboundNetData.flip();
    SSLEngineResult res;

    if(!inboundNetData.hasRemaining()) {
      return getRuntime().getNil();
    }

    res = new SSLOp(inboundNetData, appData) {
      @Override
      public SSLEngineResult run(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return engine.unwrap(src, dst);
      }
    }.doRun();
    log("AFTER INITIAL UNWRAP -> read: ", engine, res);

    HandshakeStatus handshakeStatus = engine.getHandshakeStatus();
    boolean done = false;
    log(handshakeStatus.toString());
    switch (handshakeStatus) {
      case NEED_WRAP:
        log("wrapping to outbound...");
        res = new SSLOp(appData, outboundNetData) {
          @Override
          public SSLEngineResult run(ByteBuffer src, ByteBuffer dst) throws SSLException {
            return engine.wrap(src, dst);
          }
        }.doRun();
        log("AFTER HANDSHAKE WRAP -> read: ", engine, res);
        break;
      case NEED_UNWRAP:
        while (handshakeStatus == HandshakeStatus.NEED_UNWRAP
            && !done
            && inboundNetData.hasRemaining()) {
          log("unwrapping more after handshake...");
          res = new SSLOp(inboundNetData, appData) {
            @Override
            public SSLEngineResult run(ByteBuffer src, ByteBuffer dst) throws SSLException {
              return engine.unwrap(src, dst);
            }
          }.doRun();
          handshakeStatus = engine.getHandshakeStatus();
          log("AFTER HANDSHAKE UNWRAP -> read: ", engine, res);
          if (res.getStatus() == Status.BUFFER_UNDERFLOW) {
            // need more data before we can shake more hands
            done = true;
          }

          // dm todo this dupes the case above...
          while (handshakeStatus == HandshakeStatus.NEED_WRAP) {
            log("wrapping to outbound...");
            res = new SSLOp(new MiniSSLBuffer(0), outboundNetData) {
              @Override
              public SSLEngineResult run(ByteBuffer src, ByteBuffer dst) throws SSLException {
                return engine.wrap(src, dst);
              }
            }.doRun();
            handshakeStatus = engine.getHandshakeStatus();
            log("AFTER HANDSHAKE WRAP -> read: ", engine, res);
          }
        }
        break;
    }

    inboundNetData.clear();

    ByteList appDataByteList = appData.asByteList();
    if (appDataByteList == null) {
      return getRuntime().getNil();
    }

    RubyString str = getRuntime().newString("");
    str.setValue(appDataByteList);

    log("--- Data read begin ---\n");
    log(str.asJavaString());
    log("\n--- Data read end   ---");
    return str;
  }

  private static HandshakeStatus runDelegatedTasks(HandshakeStatus hsStatus, SSLEngine engine) {

    if(hsStatus == HandshakeStatus.NEED_TASK) {
      Runnable runnable;
      while ((runnable = engine.getDelegatedTask()) != null) {
        log("\trunning delegated task...");
        runnable.run();
      }
      log("\tnew HandshakeStatus: " + hsStatus);
    }

    return hsStatus;
  }
  

  // dm todo nuke logging or put it behind a flag
  private static void log(String str, SSLEngine engine, SSLEngineResult result) {
    HandshakeStatus hsStatus = engine.getHandshakeStatus();
    log(str +
        result.getStatus() + "/" + hsStatus + ", " +
        "\n\tbytes consumed:" + result.bytesConsumed() +
        "\n\tbytes produced:" + result.bytesProduced());
    if (hsStatus == HandshakeStatus.FINISHED) {
      log("\t...ready for application data");
    }
  }

  private static void log(String str) {
    System.out.println(str);
  }

  @JRubyMethod
  public IRubyObject write(IRubyObject arg) throws javax.net.ssl.SSLException {
    log("write from: " + outboundNetData.position());

    byte[] bls = arg.convertToString().getBytes();
    ByteBuffer src = ByteBuffer.wrap(bls);

    SSLEngineResult res = engine.wrap(src, outboundNetData.getRawBuffer());

    return getRuntime().newFixnum(res.bytesConsumed());
  }

  @JRubyMethod
  public IRubyObject extract() {
    ByteList dataByteList = outboundNetData.asByteList();
    if (dataByteList == null) {
      return getRuntime().getNil();
    }

    RubyString str = getRuntime().newString("");
    str.setValue(dataByteList);

    log("-----> extracting " + dataByteList.getRealSize() + " bytes");

    return str;
  }
}
