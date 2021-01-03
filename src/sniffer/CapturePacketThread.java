package sniffer;

import javax.swing.SwingUtilities;

public abstract class CapturePacketThread {
    private Object value;
    private CreateThread createThread;
    public abstract Object construct();

    private static class CreateThread {
        private Thread thread;
        CreateThread(Thread thread) {
            this.thread = thread;
        }
        synchronized Thread get() {
            return thread;
        }
        synchronized void clear() {
            thread = null;
        }
    }

    protected synchronized Object getValue() {
        return value;
    }

    private synchronized void setValue(Object value) {
        this.value = value;
    }

    public void finished() {
    }

    public void interrupt() {
        Thread thread = createThread.get();
        if (thread != null) {
            thread.interrupt();
        }
        createThread.clear();
    }

    public CapturePacketThread() {
        final Runnable doFinished = new Runnable() {
            public void run() {
                finished();
            }
        };

        Runnable doConstruct = new Runnable() {
            public void run() {
                try {
                    setValue(construct());
                } finally {
                    createThread.clear();
                }
                SwingUtilities.invokeLater(doFinished);
            }
        };
        Thread t = new Thread(doConstruct);
        createThread = new CreateThread(t);
    }

    public void start() {
        Thread thread = createThread.get();
        if (thread != null) {
            thread.start();
        }
    }
}
