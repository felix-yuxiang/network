package ca.ubc.cs.cs317.dnslookup;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.IntStream;

public class DNSMessage {
    public static final int MAX_DNS_MESSAGE_LENGTH = 512;
    public static final int QUERY = 0;
    /**
     * TODO:  You will add additional constants and fields
     */
    private final Map<String, Integer> nameToPosition = new HashMap<>();
    private final Map<Integer, String> positionToName = new HashMap<>();
    private final ByteBuffer buffer;
    private static final int RA_QR_MASK = 0x80;
    private static final int OPCODE_MASK = 0x78;
    private static final int AA_MASK = 0b100;
    private static final int TC_MASK = 0b10;
    private static final int RD_MASK = 0b1;
    private static final int RCODE_MASK = 0xf;


    /**
     * Initializes an empty DNSMessage with the given id.
     *
     * @param id The id of the message.
     */
    public DNSMessage(short id) {
        this.buffer = ByteBuffer.allocate(MAX_DNS_MESSAGE_LENGTH);
        this.setID(id);
        buffer.position(12);
    }

    /**
     * Initializes a DNSMessage with the first length bytes of the given byte array.
     *
     * @param recvd The byte array containing the received message
     * @param length The length of the data in the array
     */
    public DNSMessage(byte[] recvd, int length) {
        buffer = ByteBuffer.wrap(recvd, 0, length);
        buffer.rewind();
        buffer.position(12);
    }

    /**
     * Getters and setters for the various fixed size and fixed location fields of a DNSMessage
     * TODO:  They are all to be completed
     */

    public int getID() {
        return buffer.getShort(0) & 0xffff;
    }

    public void setID(int id) {
        buffer.putShort(0, (short)(id & 0xffff));

    }

    public boolean getQR() {
        char secondLineHead =  buffer.getChar(2);
        boolean QR = (secondLineHead & RA_QR_MASK)>>7 == 1;
        return QR;
    }

    public void setQR(boolean qr) {
        char secondLineHead =  buffer.getChar(2);
        if (qr) {
            buffer.putChar(2, (char) (secondLineHead | RA_QR_MASK));
        } else {
            buffer.putChar(2, (char) (secondLineHead & 0x7f));
        }
    }

    public boolean getAA() {
        char secondLineHead =  buffer.getChar(2);
        boolean AA =  (secondLineHead & AA_MASK)>>2 == 1;
        return AA;
    }

    public void setAA(boolean aa) {
        char secondLineHead =  buffer.getChar(2);
        if (aa) {
            buffer.putChar(2, (char) (secondLineHead | AA_MASK));
        } else {
            buffer.putChar(2, (char) (secondLineHead & 0xfb));
        }
    }

    public int getOpcode() {
        char secondLineHead = buffer.getChar(2);
        int Opcode = (secondLineHead & OPCODE_MASK) >> 3;
        return Opcode;
    }

    public void setOpcode(int opcode) {
        char secondLineHead = buffer.getChar(2);
        buffer.putChar(2, (char) (secondLineHead & 0x87 | ((opcode & 0xf)<<3)));
    }

    public boolean getTC() {
        char secondLineHead = buffer.getChar(2);
        boolean TC = (secondLineHead & TC_MASK)>>1 == 1;
        return TC;
    }

    public void setTC(boolean tc) {
        char secondLineHead =  buffer.getChar(2);
        if (tc) {
            buffer.putChar(2, (char) (secondLineHead | TC_MASK));
        } else {
            buffer.putChar(2, (char) (secondLineHead & 0xfd));
        }
    }

    public boolean getRD() {
        char secondLineHead = buffer.getChar(2);
        boolean RD = (secondLineHead & RD_MASK) == 1;
        return RD;
    }

    public void setRD(boolean rd) {
        char secondLineHead =  buffer.getChar(2);
        if (rd) {
            buffer.putChar(2, (char) (secondLineHead | RD_MASK));
        } else {
            buffer.putChar(2, (char) (secondLineHead & 0xfe));
        }
    }

    public boolean getRA() {
        char secondLineTail = buffer.getChar(3);
        boolean RA = (secondLineTail & RA_QR_MASK)>>7 == 1;
        return RA;
    }

    public void setRA(boolean ra) {
        char secondLineTail =  buffer.getChar(3);
        if (ra) {
            buffer.putChar(2, (char) (secondLineTail | RA_QR_MASK));
        } else {
            buffer.putChar(2, (char) (secondLineTail | 0x7f));
        }
    }

    public int getRcode() {
        int Rcode = buffer.getChar(3) & RCODE_MASK;
        return Rcode;
    }

    public void setRcode(int rcode) {
        char temp = (char) ((buffer.getChar(3) & 0xf0) | ((rcode) & RCODE_MASK));
        buffer.putChar(3, temp);
    }

    public int getQDCount() {
        int QDcount = buffer.getShort(4) & 0xffff;
        return QDcount;
    }

    public void setQDCount(int count) {
        this.buffer.putShort(4, (short)(count & 0xffff));
    }

    public int getANCount() {
        int ANcount= buffer.getShort(6) & 0xffff;
        return ANcount;
    }

    public void setANCount(int count) {
        this.buffer.putShort(6, (short) (count & 0xffff));
    }

    public int getNSCount() {
        int NScount = buffer.getShort(8) & 0xffff;
        return NScount;
    }
    public void setNSCount(int count) {
        this.buffer.putShort(8, (short) (count & 0xffff));
    }

    public int getARCount() {
        int ARcount = buffer.getShort(10) & 0xffff;
        return ARcount;
    }

    public void setARCount(int count) {
        this.buffer.putShort(10, (short)(count & 0xffff));
    }

    /**
     * Return the name at the current position() of the buffer.  This method is provided for you,
     * but you should ensure that you understand what it does and how it does it.
     *
     * The trick is to keep track of all the positions in the message that contain names, since
     * they can be the target of a pointer.  We do this by storing the mapping of position to
     * name in the positionToName map.
     *
     * @return The decoded name
     */
    public String getName() {
        // Remember the starting position for updating the name cache
        int start = buffer.position();
        int len = buffer.get() & 0xff;
        if (len == 0) return "";
        if ((len & 0xc0) == 0xc0) {  // This is a pointer
            int pointer = ((len & 0x3f) << 8) | (buffer.get() & 0xff);
            String suffix = positionToName.get(pointer);
            assert suffix != null;
            positionToName.put(start, suffix);
            return suffix;
        }
        byte[] bytes = new byte[len];
        buffer.get(bytes, 0, len);
        String label = new String(bytes, StandardCharsets.UTF_8);
        String suffix = getName();
        String answer = suffix.isEmpty() ? label : label + "." + suffix;
        positionToName.put(start, answer);
        return answer;
    }

    /**
     * The standard toString method that displays everything in a message.
     * @return The string representation of the message
     */
    public String toString() {
        // Remember the current position of the buffer so we can put it back
        // Since toString() can be called by the debugger, we want to be careful to not change
        // the position in the buffer.  We remember what it was and put it back when we are done.
        int end = buffer.position();
        final int DataOffset = 12;
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("ID: ").append(getID()).append(' ');
            sb.append("QR: ").append(getQR()).append(' ');
            sb.append("OP: ").append(getOpcode()).append(' ');
            sb.append("AA: ").append(getAA()).append('\n');
            sb.append("TC: ").append(getTC()).append(' ');
            sb.append("RD: ").append(getRD()).append(' ');
            sb.append("RA: ").append(getRA()).append(' ');
            sb.append("RCODE: ").append(getRcode()).append(' ')
                    .append(dnsErrorMessage(getRcode())).append('\n');
            sb.append("QDCount: ").append(getQDCount()).append(' ');
            sb.append("ANCount: ").append(getANCount()).append(' ');
            sb.append("NSCount: ").append(getNSCount()).append(' ');
            sb.append("ARCount: ").append(getARCount()).append('\n');
            buffer.position(DataOffset);
            showQuestions(getQDCount(), sb);
            showRRs("Authoritative", getANCount(), sb);
            showRRs("Name servers", getNSCount(), sb);
            showRRs("Additional", getARCount(), sb);
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "toString failed on DNSMessage";
        }
        finally {
            buffer.position(end);
        }
    }

    /**
     * Add the text representation of all the questions (there are nq of them) to the StringBuilder sb.
     *
     * @param nq Number of questions
     * @param sb Collects the string representations
     */
    private void showQuestions(int nq, StringBuilder sb) {
        sb.append("Question [").append(nq).append("]\n");
        for (int i = 0; i < nq; i++) {
            DNSQuestion question = getQuestion();
            sb.append('[').append(i).append(']').append(' ').append(question).append('\n');
        }
    }

    /**
     * Add the text representation of all the resource records (there are nrrs of them) to the StringBuilder sb.
     *
     * @param kind Label used to kind of resource record (which section are we looking at)
     * @param nrrs Number of resource records
     * @param sb Collects the string representations
     */
    private void showRRs(String kind, int nrrs, StringBuilder sb) {
        sb.append(kind).append(" [").append(nrrs).append("]\n");
        for (int i = 0; i < nrrs; i++) {
            ResourceRecord rr = getRR();
            sb.append('[').append(i).append(']').append(' ').append(rr).append('\n');
        }
    }

    /**
     * Decode and return the question that appears next in the message.  The current position in the
     * buffer indicates where the question starts.
     *
     * @return The decoded question
     */
    public DNSQuestion getQuestion() {
        // TODO: Complete this method
        String hostname = this.getName();
        int RecordTypeCode = buffer.getShort();
        int RecordClassCode = buffer.getShort();
        return new DNSQuestion(hostname, RecordType.getByCode(RecordTypeCode), RecordClass.getByCode(RecordClassCode));
    }

    /**
     * Decode and return the resource record that appears next in the message.  The current
     * position in the buffer indicates where the resource record starts.
     *
     * @return The decoded resource record
     */
    public ResourceRecord getRR() {
        // TODO: Complete this method
        ResourceRecord outputRR = null;
//        Get the name and type of ResourceRecords
        DNSQuestion FQDNInfo = this.getQuestion();
        int TTL = buffer.getInt();
        short len = buffer.getShort();
        if (FQDNInfo.getRecordType() == RecordType.A) {
            byte[] bytes = new byte[4];
            buffer.get(bytes, 0, 4);
            try {
                outputRR = new ResourceRecord(FQDNInfo, TTL, InetAddress.getByAddress(bytes));
            } catch (UnknownHostException e) {
                e.printStackTrace();
            }
        } else if (FQDNInfo.getRecordType() == RecordType.AAAA) {
            byte[] bytes = new byte[16];
            buffer.get(bytes, 0, 16);
            try {
                outputRR = new ResourceRecord(FQDNInfo, TTL, InetAddress.getByAddress(bytes));
            } catch (UnknownHostException e) {
                e.printStackTrace();
            }
        } else if (FQDNInfo.getRecordType() == RecordType.MX) {
            short priority = buffer.getShort();
            String value = this.getName();
            outputRR = new ResourceRecord(FQDNInfo, TTL, value);
        } else {
            String result = this.getName();
            outputRR = new ResourceRecord(FQDNInfo, TTL, result);
        }


        return outputRR;
    }

    /**
     * Helper function that returns a hex string representation of a byte array. May be used to represent the result of
     * records that are returned by a server but are not supported by the application (e.g., SOA records).
     *
     * @param data a byte array containing the record data.
     * @return A string containing the hex value of every byte in the data.
     */
    public static String byteArrayToHexString(byte[] data) {
        return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
    }

    /**
     * Add an encoded name to the message. It is added at the current position and uses compression
     * as much as possible.  Compression is accomplished by remembering the position of every added
     * label.
     *
     * @param name The name to be added
     */
    public void addName(String name) {
        String label;
        while (name.length() > 0) {
            Integer offset = nameToPosition.get(name);
            if (offset != null) {
                int pointer = offset;
                pointer |= 0xc000;
                buffer.putShort((short)pointer);
                return;
            } else {
                nameToPosition.put(name, buffer.position());
                int dot = name.indexOf('.');
                label = (dot > 0) ? name.substring(0, dot) : name;
                buffer.put((byte)label.length());
                for (int j = 0; j < label.length(); j++) {
                    buffer.put((byte)label.charAt(j));
                }
                name = (dot > 0) ? name.substring(dot + 1) : "";
            }
        }
        buffer.put((byte)0);
    }

    /**
     * Add an encoded question to the message at the current position.
     * @param question The question to be added
     */
    public void addQuestion(DNSQuestion question) {
        // TODO: Complete this method
        int curQDcount = this.getQDCount();
        this.setQDCount(++curQDcount);
        this.addName(question.getHostName());
        this.addQType(question.getRecordType());
        this.addQClass(question.getRecordClass());
    }

    /**
     * Add an encoded resource record to the message at the current position.
     * @param rr The resource record to be added
     * @param section A string describing the section that the rr should be added to
     */
    public void addResourceRecord(ResourceRecord rr, String section) {
        // section parameter determines which part of count we need to increment
        if (section.equals("answer")) {
            int curANcount = this.getANCount();
            this.setANCount(++curANcount);
        } else if (section.equals("nameserver")) {
            int curNScount = this.getNSCount();
            this.setNSCount(++curNScount);
        } else {
            int curARcount = this.getARCount();
            this.setARCount(++curARcount);
        }

        this.addName(rr.getHostName());
        this.addQType(rr.getRecordType());
        this.addQClass(rr.getRecordClass());
        buffer.putInt((int) rr.getRemainingTTL());
        if (rr.getRecordType() == RecordType.A) {
            buffer.putShort((short) 4);
            byte[] bytes = rr.getInetResult().getAddress();
            buffer.put(bytes);
        } else if (rr.getRecordType() == RecordType.AAAA) {
            buffer.putShort((short) 16);
            byte[] bytes = rr.getInetResult().getAddress();
            buffer.put(bytes);
        } else if (rr.getRecordType() == RecordType.MX) {
            buffer.putShort((short) rr.getTextResult().length());
            short priority = 0;
            buffer.putShort(priority);
            this.addName(rr.getTextResult());
        } else {
            buffer.putShort((short) rr.getTextResult().length());
            this.addName(rr.getTextResult());
        }
    }

    /**
     * Add an encoded type to the message at the current position.
     * @param recordType The type to be added
     */
    private void addQType(RecordType recordType) {
        // TODO: Complete this method
        buffer.putShort((short) recordType.getCode());
    }

    /**
     * Add an encoded class to the message at the current position.
     * @param recordClass The class to be added
     */
    private void addQClass(RecordClass recordClass) {
        // TODO: Complete this method
        buffer.putShort((short) recordClass.getCode());
    }

    /**
     * Return a byte array that contains all the data comprising this message.  The length of the
     * array will be exactly the same as the current position in the buffer.
     * @return A byte array containing this message's data
     */
    public byte[] getUsed() {
        // TODO: Complete this method
        int finishIndex = buffer.position();
        buffer.position(0);
        byte[] bytes = new byte[finishIndex];
        buffer.get(bytes, 0, finishIndex);
        return bytes;
    }

    /**
     * Returns a string representation of a DNS error code.
     *
     * @param error The error code received from the server.
     * @return A string representation of the error code.
     */
    public static String dnsErrorMessage(int error) {
        final String[] errors = new String[]{
                "No error", // 0
                "Format error", // 1
                "Server failure", // 2
                "Name error (name does not exist)", // 3
                "Not implemented (parameters not supported)", // 4
                "Refused" // 5
        };
        if (error >= 0 && error < errors.length)
            return errors[error];
        return "Invalid error message";
    }
}
