package IEEE_TDSC;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.Random;



public class AuthenticationServer {


    public static String Plaintext;
    public static String encryptedString;
    public static int PlaintextLength = 16;
    public static int RSA_Key_length = 4096;
    public static int AES_Key_Length = 256;
    public static int Random_Number_Length = 128;
    public static int Random_String_Key_Length = 128;
    public static int k_DoS = 3;

    public static String Common_RSA_Certificate_Path = "E:/OneDrive/PhD Ireland/PhD Work/MEC/Research Directions/Service Migration Prediction/Implementation/AwaneeshWirelessLightWeightProtocol/out/production/AwaneeshWirelessLightWeightProtocol/";
    public static String Entity_AS = "AS", Entity_C = "C";
    public static String PW = "EAPPSMFP";

    public static String String_K1 = "058144097095083141195194042117201069162080253211";
    public static String String_K2 = "098161112180192095183011072194020174162026207008";
    public static BigInteger K1, K2;

    public static int aes;
    public static float des;
    public static BigInteger rsa;

    public static int PORT = 1022;

    public static long Start_time;
    public static long End_time;
    public static long Process_time;
    public static long Received_time;
    public static long Sending_time;
    public static long Current_time;
    public static Long T;

    public KeyFactory keyFactory;
    public PrivateKey privateKey_AS = null;
    public PublicKey publicKey_AS = null;

    public BigInteger r1,r2,r3;
    public String Km,SK;

    //IDs
    public static String AP_Tid = "10.0.0.255";
    public static String C_Tid = "10.0.0.1";
    public static String S_id = "10.0.0.100";

    public static String input;


    //Secret Key for DES
    public static final String SECRET_KEY_DES = "wo/**bhd";

    //Secret Key and Salt for the AESEncrypt() and AESDecrypt() Functions
    public static String SECRET_KEY = null;
    public static final String SALT = "ssshhhhhhhhhhh!!!!";


    public AuthenticationServer()throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, Exception{

        System.out.println("RSA based Certificate Creation Begins at ....."+getCurrentTimestamp()+"\n\n");

        //Generating the RSA Certificates at the given Location for Each Entity
        //RSA_generate_keys(Common_RSA_Certificate_Path, Entity_AS);
        //RSA_generate_keys(Common_RSA_Certificate_Path, Entity_C);

        //Loading the RSA keys of this Entity
        RSA_load_own_keys(Common_RSA_Certificate_Path,Entity_AS);
        //RSA_load_public_key(Common_RSA_Certificate_Path,Entity_C);

        System.out.println("RSA Key Generation and Loading Concluded at "+getCurrentTimestamp()+"....");

        VerticalSpace();

        //Converting Pre-shared Keys to BigIntegers
        //Integer K1_int = Integer.parseInt(String_K1);
        //Integer K2_int = Integer.parseInt(String_K2);

        K1 = new BigInteger(String_K1);
        K2 = new BigInteger(String_K2);

        System.out.println("K1 = "+K1);
        System.out.println("K2 = "+K2);

        //Defining Clock Skew in Milliseconds
        T = new Long("5000");



        ServerSocket serverSocket = new ServerSocket(PORT);

        try {

            while (true) {

                VerticalSpace();
                System.out.println("SERVER IS READY. AWAITING CONNECTION.....");
                VerticalSpace();

                Socket socket = serverSocket.accept();

                try {

                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                    String input;



                    VerticalSpace();

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%   Message 1   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                    input = in.readLine();

                    Received_time = System.currentTimeMillis();

                    System.out.println("Message 1 from IEEE_TDSC.Client: "+input+" received at.."+new Timestamp(TSNanoToMilliseconds(Received_time)));

                    //Segmenting the Message 1
                    String Message_1[] = input.split(" ");

                    //Assigning Received Message segments to the parameters
                    String R1_received = Message_1[0];
                    Long T1 = new Long(Message_1[1]);
                    String C_Mid_received = Message_1[2];
                    String r1_dash_received = Message_1[3];

                    BigInteger r1_dash = new BigInteger(r1_dash_received);

                    //Selecting T2
                    Current_time = System.currentTimeMillis();
                    System.out.println("T2 TS: "+new Timestamp(Current_time));
                    Long T2 = Current_time;

                    System.out.println("T2 : "+T2);

                    System.out.println("Received T1 : "+T1);

                    //Initializing r2
                    SecureRandom Secure_r2 = new SecureRandom();
                    r2 = new BigInteger(Random_Number_Length, Secure_r2);
                    System.out.println("r2 : "+r2);

                    Long TimeDifference = TSDifference(T1,T2);
                    System.out.println("T2 - T1 [ms] = "+TimeDifference);

                    //Timestamp Check
                    if ( TimeDifference < T ){

                        System.out.println("The Received message is within the defined clock skew T = "+T);
                        //Computing r1 and Km
                      r1 = r1_dash.xor(K1);
                      Km = Hash(K2.toString()+r1.toString());

                      //Specifying Km as the Secret Key of the AES Algorithm
                      SECRET_KEY = Km;

                      //Decrypting R1
                        String DecryptedPayload_1[] = AES_Decrypt(R1_received).split(" ");

                        //Assigning Decrypted Elements to Parameters
                        Long Decrypted_T1 = new Long(DecryptedPayload_1[0]);
                        String Decrypted_PW = DecryptedPayload_1[1];
                        String Decrypted_C_Mid = DecryptedPayload_1[2];
                        String Decrypted_r1_dash = DecryptedPayload_1[3];

                        //Checking the INTEGRITY
                        if ((T1.equals(Decrypted_T1)) && (PW.matches(Decrypted_PW)) && (C_Mid_received.matches(Decrypted_C_Mid)) && (r1_dash_received.matches(Decrypted_r1_dash))){

                            System.out.println("INTEGRITY Check Result : Integrity Secured...............");

                        }else {

                            System.out.println("INTEGRITY Check Result : Integrity Violated...............");

                        }

                    }else{

                        System.out.println("ERROR : The Received Message is not FRESH..........");
                    }

                    System.out.println("Time taken for Message 1 Processing [ms] : "+(System.currentTimeMillis()-Received_time));

                    VerticalSpace();

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  MESSAGE 2 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                    //Both AP_Tid and C_Tid are already specified on top

                    //Kf
                    String Kf = RandomStringKeyGenerator();
                    //C_MTid = H(C_Tid)
                    String C_MTid = Hash(C_Tid);

                    //Re=(Kf||CMTid||CTid||APTid)
                    String Re = Kf+C_MTid+C_Tid+AP_Tid;

                    //r2'=(r1⊕r2)
                    BigInteger r2_dash = r1.xor(r2);

                    //R2 = E_Km(T2||r2'||Sid||Re||k_DoS)
                    String Payload_2 = T2+" "+r2_dash+" "+S_id+" "+Re+" "+k_DoS;
                    String R2 = AES_Encrypt(Payload_2);
                    System.out.println("AES Encrypted Payload 2 = R2 : "+R2);

                    //Forming Message 2
                    String Message_2 = R2+" "+T2+" "+Re;

                    //Sending Message 2
                    out.println(Message_2);
                    Sending_time = System.currentTimeMillis();

                    System.out.println("Message 2 : "+Message_2);
                    System.out.println("Sent at : "+new Timestamp(Sending_time));
                    System.out.println("Processing Time [ms]: "+(System.currentTimeMillis()-Received_time));

                    VerticalSpace();


                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%   Message 3   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                    input = in.readLine();

                    Received_time = System.currentTimeMillis();

                    System.out.println("Message 3 from IEEE_TDSC.Client: "+input+" received at.."+new Timestamp(Received_time));

                    //Segmenting the Message 1
                    String Message_3[] = input.split(" ");

                    //Assigning Received Message segments to the parameters
                    String R3 = Message_3[0];
                    Long T3 = new Long(Message_3[1]);

                    //Selecting T4
                    Current_time = System.currentTimeMillis();
                    System.out.println("T4 : "+Current_time);
                    Long T4 = Current_time;

                    TimeDifference = TSDifference(T3,T4);
                    System.out.println("T4 - T3 [ms] = "+TimeDifference);

                    //Timestamp Check >>> T4-T3 <= T
                    if ( TimeDifference < T ){

                        System.out.println("The Received message is within the defined clock skew T [ms] = "+T);

                        //Decrypting R3 >>>> DPRS(R3)={r2*, T3*, r3*}
                        String DecryptedPayload_3 = RSA_decrypt(R3,privateKey_AS);

                        System.out.println("Decrypted Payload : "+DecryptedPayload_3);

                        String[] DecryptedPayloadArray_3 = DecryptedPayload_3.split(" ");

                        //Assigning Decrypted Elements to Parameters
                        BigInteger Decrypted_r2 = new BigInteger(DecryptedPayloadArray_3[0]);
                        Long Decrypted_T3 = new Long(DecryptedPayloadArray_3[1]);
                        r3 = new BigInteger(DecryptedPayloadArray_3[2]);
                        String X = DecryptedPayloadArray_3[3];

                        //Verifying the DoS Puzzle
                        DoS_Puzzle_Verification(k_DoS,publicKey_AS.toString(),C_Tid,S_id,C_Mid_received,K1.toString(),X);

                        //Checking the INTEGRITY
                        if ((T3.equals(Decrypted_T3)) && (r2.equals(Decrypted_r2))){

                            System.out.println("INTEGRITY Check Result : Integrity Secured...............");

                        }else {

                            System.out.println("INTEGRITY Check Result : Integrity Violated...............");

                        }

                    }else{

                        System.out.println("ERROR : The Received Message is not FRESH..........");
                    }

                    System.out.println("Time taken for Message 3 Processing [ms] : "+(System.currentTimeMillis()-Received_time));

                    VerticalSpace();



                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  MESSAGE 4 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                    //Session Key Generation

                    //SK=H(r1||r2||r3)
                    SK = Hash(r1.toString()+r2.toString()+r3.toString());

                    System.out.println("Generated Session Key - SK : "+SK);

                    //Forming Message 2
                    String Message_4 = "EAP-Successful";

                    //Sending Message 2
                    out.println(Message_4);
                    Sending_time = System.currentTimeMillis();

                    System.out.println("Message 4 : "+Message_2);
                    System.out.println("Sent at : "+new Timestamp(Sending_time));
                    System.out.println("Processing Time [ms]: "+(System.currentTimeMillis()-Received_time));

                    VerticalSpace();

                    System.out.println("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  MUTUAL AUTHENTICATION ESTABLISHED ........... ");

                    VerticalSpace();


                } finally {
                    socket.close();
                }
            }

        } finally {
            serverSocket.close();

        }



    }



    public static void main(String[] args) throws UnknownHostException, Exception {

        System.out.println("Authentication Server (AS) is Running at..\n"+getCurrentTimestamp()+"\n\n");

        //Socket Constructor
        AuthenticationServer AS = new AuthenticationServer();


    }

    //////////////////////////////////////////////////  FUNCTIONS  ///////////////////////////////////////////////////////////

    public void VerticalSpace(){

        System.out.println("\n\n");
    }

    //Function to get the current Time Stamp
    public static Timestamp getCurrentTimestamp(){
        return new Timestamp(System.currentTimeMillis());
    }

    public static Timestamp getCurrentTS(){
        return new Timestamp(System.currentTimeMillis());
    }

    public long TSDifference (long CheckingTS, long CurrentTS){

        return ((CurrentTS - CheckingTS)/1000000);
    }

    public long TSNanoToMilliseconds (long TS){

        return (TS/1000000);

    }

    ///////////////////////////   ID / MIH Checking Functions //////////////////////////////////////////
    public boolean Check_String(String Received_String, String Checking_String){

        return Checking_String.matches(Received_String);
    }


    public static String RandomNonceGenerator() {
        int leftLimit = 97; // letter 'a'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = 10;
        Random random = new Random();

        String generatedString = random.ints(leftLimit, rightLimit + 1)
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        return generatedString;
    }

    public static String RandomStringKeyGenerator() {
        int leftLimit = 97; // letter 'a'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = Random_String_Key_Length;
        Random random = new Random();

        String generatedKey = random.ints(leftLimit, rightLimit + 1)
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        return generatedKey;
    }

    /////////////////////////////////   DoS PUZZLE  /////////////////////////////////////////////

    public String DoS_Puzzle(int k_dos, String PublicKey,  String Client_ID, String Server_ID, String Client_Nonce, String Server_Nonce) throws UnknownHostException, Exception{

        long j = 0;

        String X;

        System.out.println("\n\nDoS PUZZLE STARTING...........");

        long ts_start = System.currentTimeMillis();

        while (true){

            X = RandomNonceGenerator();


            String BIhash = BIHash(PublicKey + Client_ID + Client_Nonce + Server_ID + Server_Nonce + X);

            if (CheckZeroCount(BIhash,k_dos)==true){
                System.out.println("SOLUTION FOUND....X = "+X);
                break;
            }

            j++;

        }

        long ts_end = System.currentTimeMillis();

        System.out.println("Number of Attempts :"+j);
        System.out.println("DoS Puzzle Process Time [ms]:"+(ts_end-ts_start));

        return X;

    }

    public void DoS_Puzzle_Verification(int k_dos, String PublicKey,  String Client_ID, String Server_ID, String Client_Nonce, String Server_Nonce, String X) throws UnknownHostException, Exception{

        String VerifyingHash = BIHash(PublicKey + Client_ID + Client_Nonce + Server_ID + Server_Nonce + X);

        System.out.println("Received X : " + X);
        System.out.println("Verifying Hash : " + VerifyingHash);

        if (CheckZeroCount(VerifyingHash,k_dos)){
            System.out.println(".................The DoS Puzzle is VERIFIED..............\n\n");
        }else {

            System.out.println(".............The DoS Puzzle is Not Verified ==> DoS Attack Detected..........\n\n");
        }

    }

    public static String BIHash (String message) throws NoSuchAlgorithmException {

        String HashAlgorithm = "SHA-512";

        // getInstance() method is called with algorithm SHA-512
        MessageDigest md = MessageDigest.getInstance(HashAlgorithm);

        int k = 155;
        // digest() method is called
        // to calculate message digest of the input string
        // returned as array of byte
        byte[] messageDigest = md.digest(message.getBytes());

        // Convert byte array into signum representation
        BigInteger no = new BigInteger(1, messageDigest);

        int BIlength = no.toString().length();

        //System.out.println("BI Length = "+BIlength);

        String hash = no.toString();

        if( BIlength < k ){
            for(int i=0; i < (k-BIlength); i++){
                hash = "0"+hash;
            }
        }

        //System.out.println("Modified Hash : "+hash);
        //System.out.println("Modified Hash Length: "+hash.length());

        return  hash;
    }

    public static Boolean CheckZeroCount(String hash, int k_dos){

        char[] hashArray = hash.toCharArray();
        Boolean Check = false;

        for(int i=0; i < k_dos ; i++){


            if (hashArray[i] == '0'){
                Check = true;
            }else {
                Check = false;
                break;
            }
        }
        return Check;

    }


    /////////////////////////////////   HASHING FUNCTIONS   //////////////////////////////////////

    public static String Hash (String message) throws NoSuchAlgorithmException {
        // getInstance() method is called with algorithm SHA-512
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // digest() method is called
        // to calculate message digest of the input string
        // returned as array of byte
        byte[] messageDigest = md.digest(message.getBytes());

        // Convert byte array into signum representation
        BigInteger no = new BigInteger(1, messageDigest);

        // Convert message digest into hex value
        String hashtext = no.toString(16);

        // Add preceding 0s to make it 32 bit
        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }

        // return the HashText
        return hashtext;
    }

    public boolean CheckHash(String CheckingHash, String TargetHash){

        return CheckingHash.matches(TargetHash);
    }

    /////////////////////////// RSA /////////////////////////////////////////////
    public static void RSA_generate_keys (String Certificate_Path, String Entity_Name) throws NoSuchAlgorithmException, IOException{

        // Get an instance of the RSA key generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(RSA_Key_length);

        // Generate the KeyPair
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Get the public and private key
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("Entity Name : "+Entity_Name);

        System.out.println("RSA Private Key : "+privateKey);
        System.out.println("RSA Public Key : "+publicKey);

        //Creating the Files for storing the Private and Public Keys

        File privateKeyFile = new File(Certificate_Path+"PRIVATE_KEY_"+Entity_Name+".txt");
        privateKeyFile.createNewFile();

        File publicKeyFile = new File(Certificate_Path+"PUBLIC_KEY_"+Entity_Name+".txt");
        publicKeyFile.createNewFile();

        byte[] encodedPublicKey = publicKey.getEncoded();
        String b64PublicKey = Base64.getEncoder().encodeToString(encodedPublicKey);

        byte[] encodedPrivateKey = privateKey.getEncoded();
        String b64PrivateKey = Base64.getEncoder().encodeToString(encodedPrivateKey);

        //Writing the Keys to the created files
        try (OutputStreamWriter publicKeyWriter =
                     new OutputStreamWriter(
                             new FileOutputStream(publicKeyFile),
                             StandardCharsets.US_ASCII.newEncoder())) {
            publicKeyWriter.write(b64PublicKey);
        }

        try (OutputStreamWriter privateKeyWriter =
                     new OutputStreamWriter(
                             new FileOutputStream(privateKeyFile),
                             StandardCharsets.US_ASCII.newEncoder())) {
            privateKeyWriter.write(b64PrivateKey);
        }

        System.out.println("Certificate is generated of the Entity "+Entity_Name+" at"+getCurrentTimestamp()+"\n\n");

    }

    public void RSA_load_own_keys(String Certificate_Path, String Entity_Name) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

        KeyFactory kf = KeyFactory.getInstance("RSA");

        InputStream is = this.getClass().getClassLoader().getResourceAsStream("PRIVATE_KEY_"+Entity_Name+".txt");

        String stringPrivateKey = new String(is.readAllBytes());
        is.close();

        System.out.println("Loaded String Private Key : "+stringPrivateKey);

        byte[] decodedPrivateKey = Base64.getDecoder().decode(stringPrivateKey);

        //System.out.println("Decoded Private Key : "+decodedPrivateKey);

        KeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decodedPrivateKey);

        //System.out.println("Key Specification of Private Key : "+keySpecPrivate);

        PrivateKey privateKey = kf.generatePrivate(keySpecPrivate);

        privateKey_AS = privateKey;

        is = this.getClass().getClassLoader().getResourceAsStream("PUBLIC_KEY_"+Entity_Name+".txt");

        String stringPublicKey = new String(is.readAllBytes());
        is.close();

        System.out.println("Loaded String Public Key : "+stringPublicKey);

        byte[] decodedPublicKey = Base64.getDecoder().decode(stringPublicKey);

        KeySpec keySpecPublic = new X509EncodedKeySpec(decodedPublicKey);

        PublicKey publicKey = kf.generatePublic(keySpecPublic);

        publicKey_AS = publicKey;

        System.out.println("Entity Name : "+Entity_Name);
        System.out.println("Loaded RSA Private Key : "+privateKey);
        System.out.println("Loaded RSA Public Key : "+publicKey);

    }

    public PublicKey RSA_load_public_key(String Certificate_Path, String Entity_Name) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

        KeyFactory kf = KeyFactory.getInstance("RSA");

        InputStream is = this.getClass().getClassLoader().getResourceAsStream("PUBLIC_KEY_"+Entity_Name+".txt");

        String stringPublicKey = new String(is.readAllBytes());
        is.close();

        System.out.println("Loaded String Public Key : "+stringPublicKey);

        byte[] decodedPublicKey = Base64.getDecoder().decode(stringPublicKey);

        KeySpec keySpecPublic = new X509EncodedKeySpec(decodedPublicKey);

        PublicKey publicKey = kf.generatePublic(keySpecPublic);

        System.out.println("Entity Name : "+Entity_Name);
        System.out.println("Loaded RSA Public Key : "+publicKey);

        return publicKey;

    }

    public static byte[] RSA_encrypt (String plainText, PublicKey publicKey ) throws Exception
    {
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");
        //Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");

        //Initializing the Cipher only with the RSA without any padding or a BLock Cipher Mode
        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //Perform Encryption
        //byte[] cipherTextArray = cipher.doFinal(plainText.getBytes()) ;

        byte[] plainTextArray = null;

        try {
            plainTextArray = plainText.getBytes();
        } catch(ArrayIndexOutOfBoundsException e) {
            System.out.println(e);
        }

        byte[] cipherText = cipher.doFinal(plainTextArray) ;

        return cipherText;

        //return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    public static String RSA_sign (String plainText, PrivateKey privateKey) throws Exception
    {
        //byte[] plainTextArray = plainText.getBytes();

        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

        //Initialize Cipher for DECRYPT_MODE
        //cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        //Perform Decryption
        //return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));

        System.out.println("Private Key for Signing : "+privateKey);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(plainText.getBytes());

        byte[] signatureBytes = signature.sign();

        return Base64.getEncoder().encodeToString(signatureBytes);

        //return signatureBytes;
    }

    public static String RSA_decrypt (String cipherText, PrivateKey privateKey) throws Exception
    {
        byte[] cipherTextArray = Base64.getDecoder().decode(cipherText);
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");
        //Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");

        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        //Perform Decryption
        return new String(cipher.doFinal(cipherTextArray));
    }

    public static boolean RSA_verify (String VerifyingSignature, String signatureString, PublicKey publicKey ) throws Exception
    {
        //byte[] signatureArray = Base64.getDecoder().decode(signature);

        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

        //Initializing the Cipher only with the RSA without any padding or a BLock Cipher Mode
        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        //Initialize Cipher for DECRYPT_MODE for VERIFYING
        //cipher.init(Cipher.DECRYPT_MODE, publicKey);

        //Perform Verifying
        //return new String(cipher.doFinal(signatureArray));
        Signature signature = Signature.getInstance("SHA256withRSA");

        signature.initVerify(publicKey);
        signature.update(VerifyingSignature.getBytes());

        byte[] signatureBytes = Base64.getDecoder().decode(signatureString);

        return signature.verify(signatureBytes);

        //return new String(Base64.getDecoder().decode(signatureString));

    }

    /*
    //@@@@@@@@@@@@@@@@@@@@@@@@  RSA Encryption Algorithm @@@@@@@@@@@@@@@@@@@@@@

    //Function for computing RSA public parameters for the OSS CA
    public static void RSA(){
        SecureRandom r = new SecureRandom();
        BigInteger p = new BigInteger(RSA_bit_length,100,r);
        BigInteger q = new BigInteger(RSA_bit_length,100,r);
        N_s = p.multiply(q);
        BigInteger n =
                (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e_s = new BigInteger("3");
        while(n.gcd(e_s).intValue()>1){
            e_s = e_s.add(new BigInteger("2"));
        }
        d_s = e_s.modInverse(n);
    }
    //Function for RSA Encrypting
    public static BigInteger RSAencrypt (BigInteger message, BigInteger ex, BigInteger Nx){
        return message.modPow(ex, Nx);
    }
    //Function for RSA Decryption
    public static BigInteger RSAdecrypt (BigInteger message, BigInteger dx, BigInteger Nx){
        return message.modPow(dx, Nx);
    }

    //Function for RSA Signing
    public static BigInteger RSAsign (BigInteger message, BigInteger dx, BigInteger Nx){
        return message.modPow(dx, Nx);
    }
    //Function for RSA Un-signing
    public static BigInteger RSAunsign (BigInteger message, BigInteger ex, BigInteger Nx){
        return message.modPow(ex, Nx);
    }
    */

    //@@@@@@@@@@@Advanced Encryption Standard (AES) @@@@@@@@@@@@@@@@@@@@@@
/*
    public static void AES_Parameters (String myKey){

        MessageDigest sha = null;
        try {
            AES_key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            AES_key = sha.digest(AES_key);
            AES_key = Arrays.copyOf(AES_key, 16);
            AES_secretKey = new SecretKeySpec(AES_key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }


    }

    public static String AES_encrypt(String strToEncrypt, String secret)
    {
        try
        {
            AES_Parameters(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, AES_secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String AES_decrypt(String strToDecrypt, String secret)
    {
        try
        {
            AES_Parameters(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, AES_secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e)
        {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public static IvParameterSpec generateIv(byte[] iv) {
        iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String AESencrypt(String input, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String AESdecrypt(String cipherText, SecretKey key, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }
*/
    public static String AES_Encrypt(String strToEncrypt) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return Base64.getEncoder()
                    .encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String AES_Decrypt(String strToDecrypt) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

}
