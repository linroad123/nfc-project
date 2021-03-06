package com.example.auth.ticket;

import com.example.auth.app.ulctools.Commands;
import com.example.auth.app.ulctools.Utilities;

import java.security.GeneralSecurityException;

/**
 * TODO: Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets.
 */
public class Ticket {

    private static byte[] defaultAuthenticationKey = "BREAKMEIFYOUCAN!".getBytes();// 16-byte key

    /** TODO: Change these according to your design. Diversify the keys. */
    private static byte[] authenticationKey = defaultAuthenticationKey;// 16-byte key
    private static byte[] hmacKey = "0123456789ABCDEF".getBytes(); // min 16-byte key

    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private Boolean isValid = false;
    private int remainingUses = 0;
    private int expiryTime = 0;

    private static String infoToShow; // Use this to show messages
    
    //
    private final String SECRET_MESSAGE = "Crackme";
    private final byte[] TAG = "ABCD".getBytes();
    private final byte[] VERSION = {(byte)777, (byte)0, (byte)0, (byte)0};
    private final boolean DEFAULT_KEY = false;
    private final byte[] MAX_RIDE = {(byte)5, (byte)0,(byte)0,(byte)0 };
    private final int max_ride = 5;

    /** Create a new ticket */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(hmacKey);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /** After validation, get ticket status: was it valid or not? */
    public boolean isValid() {
        return isValid;
    }

    /** After validation, get the number of remaining uses */
    public int getRemainingUses() {
        return remainingUses;
    }

    /** After validation, get the expiry time */
    public int getExpiryTime() {
        return expiryTime;
    }

    /** After validation/issuing, get information */
    public static String getInfoToShow() {
        String tmp = infoToShow;
        infoToShow = "";
        return tmp;
    }


    // hash function SHA-256 output 256 bits 32 bytes
    private byte[] getHash(byte[] origin){
        byte[] res = null;
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            res = sha256.digest(origin);
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return res;
    }

    // Mac generate
    private  byte[] calculateMac(){
        // set max_ride on OTP
        boolean setmaxride = utils.writePages(MAX_RIDE, 0, 3,1);
        byte[] data = new byte[12];
        boolean resRead = utils.readPages(0, 3, data, 0);
        if(resRead){
            byte[] mac = macAlgorithm.generateMac(data);
        }
        byte[] trunctedMac = Arrays.copyOf(mac, mac.length / 5);;
        return trunctedMac;
    }
    // check if MAC is modified
    private boolean checkMAC(byte[] mac) {
        byte[] macInCard = new byte[4];
        utils.readPages(8,1,macInCard, 0);
        return compareArray(mac, macInCard);
    }

    // Mac issue
    private void issueMAC(){
        byte[] mac = calculateMac();
        boolean resWrite = utils.writePages(mac, 0, 8,1);
        if(resWrite){
            infoToShow = "WRITE MAC OK";
        }
    }
    
    public static byte[] byteMerger(byte[] bt1, byte[] bt2){  
        byte[] bt3 = new byte[bt1.length+bt2.length];  
        System.arraycopy(bt1, 0, bt3, 0, bt1.length);  
        System.arraycopy(bt2, 0, bt3, bt1.length, bt2.length);  
        return bt3;  
    } 

    // create authenticate key
    private byte[] createKey(boolean defaultKey){
        if (defaultKey)
            return defaultAuthenticationKey;
            //return resetKey;

        // get UID (serial number)
        byte[] uid = new byte[12];
        // starting page:0, ending page:3, store at uid, begin with 0 page
        utils.readPages(0, 3, uid, 0);
        uid = Arrays.copyOf(uid, 9);

        // K = h(master secret | UID)

        byte[] uidSecretMessage = byteMerger(uid, SECRET_MESSAGE.getBytes());
        byte[] fullKey = getHash(uidSecretMessage);

        // truncate the key to half length
        byte[] newkey = Arrays.copyOf(fullKey, fullKey.length / 2);

        return newkey;
    }

    private void issueKey(){
        byte[] key = createKey(DEFAULT_KEY);
        boolean res = utils.writePages(key, 0, 44, 4);

        if (res){
            infoToShow = "Wrote: " + new String("KEY OK");
        } else {
            infoToShow = "Failed to write key";
        }
    }

    private boolean authenNewKey(){
        byte[] key = createKey(DEFAULT_KEY);
        boolean res = utils.authenticate(key) ;
        if (res){
            infoToShow = "Wrote: " + new String("AUTHENTICATE OK");
            return true;
        } else {
            infoToShow = "Failed to authenticate";
            return false;
        }
    }

    private void issueTagVersion(){
        utils.writePages(TAG,0, 4, 1);
        utils.writePages(VERSION, 0, 5, 1);
    }

    // Require authentication on all writable pages.
    private  final byte[] AUTH0 = {(byte)3, (byte)0,(byte)0,(byte)0 };
    // Neither allow read nor write operations without authentication.
    private  final byte[] AUTH1 = {(byte)0, (byte)0,(byte)0,(byte)0 };
    private void issueAUTH(){
        utils.writePages(AUTH0, 0, 42, 1);
        utils.writePages(AUTH1, 0, 43, 1);
    }

    // clear Expiry Date and number of rides
    private void resetDateNoR(){
        byte[] zero = {(byte)0,(byte)0,(byte)0,(byte)0};
        utils.writePages(zero, 0, 6, 1);
        utils.writePages(zero, 0, 7, 1);
    }

    // Issue tickets with constant number of rides (5)
    private int issueNoR(){
        int counter = readCounter();
        counter = counter + max_ride;

        byte[] noR = intToByte(counter);
        utils.writePages(noR, 0, 7, 1);
        return counter;
    }
    // extend the number of ride to 5
    private int extendNoR(){
        remainingUses = readRemainUses();
        remainingUses = remainingUses + 5;

        byte[] noR = intToByte(remainingUses);
        utils.writePages(noR, 0, 7, 1);
        return remainingUses;
    }

    private byte[] getDate(){
        byte[] date = new byte[4];
        utils.readPages(6,1,date,0);
        return date;
    }

    private  boolean checkExpiryDate(byte[] dateInCard){
        Date date = new Date(); 
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);

        int year = cal.get(Calendar.YEAR);
        int month = cal.get(Calendar.MONTH);
        int day = cal.get(Calendar.DAY_OF_MONTH);
        byte[] now = {(byte)(year - 2000), (byte)(month + 1), (byte)day, (byte)0};
        return !compareArraySmallerOrEqual(now, dateInCard); //true if expired

    }

    private boolean checkSafeLimits(byte[] expiryDate, int remainingUses){
        Date date = new Date();
        Calendar cal = Calendar.getInstance();
  
        cal.setTime(date);
        int year = (int)expiryDate[0] + 2000;
        int month = (int)expiryDate[1] - 1;
        int day = (int)expiryDate[2];
        Calendar nowCal = Calendar.getInstance();
        nowCal.clear();
        nowCal.set(Calendar.YEAR, year);
        nowCal.set(Calendar.MONTH, month);
        nowCal.set(Calendar.DAY_OF_MONTH, day);
        Date expiry = nowCal.getTime();
        long diff = expiry.getTime()  - date.getTime();
        long d = TimeUnit.DAYS.convert(diff, TimeUnit.MILLISECONDS);
        if (d > 2)
            return false;
  
        int counter = readCounter();
        if (remainingUses - counter > 5){
            return false;
        }
        return true;
        //true is safe
  
      }

    private  boolean compareArraySmallerOrEqual(byte[] a1, byte[] a2){
        try {
            for (int i = 0; i < a1.length; i++){
                if (a1[i] > a2[i])
                    return false;
            }
        }
        catch (ArrayIndexOutOfBoundsException e){
            e.printStackTrace();
        }
            return true;
    }
    

    private int byteToInt(byte[] b) {
        return ((b[1] & 0xff) << 8) | b[0] & 0xff;
    }

    private byte[] intToByte(int i) {
        return new byte[]{(byte) (i & 0xff), (byte) ((i >> 8) & 0xff)};
    }

    // Counter part
    private int readCounter(){
        byte[] counterByte = new byte[4];
        utils.readPages(41, 1, counterByte, 0);
        int counter = bytesToInt(counterByte);
        return counter;
    }

    /**
     * Issue new tickets
     *
     * TODO: IMPLEMENT
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res;

        // Authenticate fail
        res = utils.authenticate(authenticationKey);
                // first time format the card
        if (res) {
            issueKey();
            authenNewKey();
            issueTagVersion();
            resetDateNoR();
            remainingUses = issueNoR();
            issueMAC();
            issueAUTH();
            infoToShow = "First time format this card";
            return true;
        } 

        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        if (!authenNewKey()){
            infoToShow = "Authentication Failed";
            return false;
         }

        byte[] mac = calculateMac();
        if (!checkMAC(mac)) {
            infoToShow = "Data is modified, this card is cracked.";
            return false;
        }

        // check if the card is expired
        byte[] expiryDateFromCard = getDate();
        byte[] zero = {(byte)0,(byte)0,(byte)0,(byte)0 };
        if (compareArray(expiryDateFromCard,zero)){
            extendNoR();
            infoToShow = "You haven't use the card for the first time. Add 5 more time to play ";
            return true;
        }else if (checkExpiryDate(expiryDateFromCard)) { 
            issueKey();
            authenNewKey();
            issueTagVersion();
            resetDateNoR();
            remainingUses = issueNoR();
            issueMAC();
            issueAUTH();
            infoToShow = "The expiry date is over, this card is being resetting now";
            return true;
        }

        int remainUses = readRemainUses();
        if (!checkSafeLimits(expiryDateFromCard, remainingUses)){
            infoToShow="We detect the suspicious activities in your card. We will detain your card.";
            return false;
        }
    

        return true;
    }


    private int readRemainUses(){
        byte[] res = new byte[4];
        utils.readPages(7, 1, res, 0);
        return bytesToInt(res);
    }
    /**
     * Use ticket once
     *
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;

        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        // Example of reading:
        byte[] message = new byte[4];
        res = utils.readPages(6, 1, message, 0);

        // Set information to show for the user
        if (res) {
            infoToShow = "Read: " + new String(message);
        } else {
            infoToShow = "Failed to read";
        }

        return true;
    }
}

