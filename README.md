# SAP_IoT-WLAN_EAP
A Secure Authentication Protocol for IoT-WLAN using EAP framework

Prefereable IDE : IntelliJ IDEA 
Import all the files under a package IEEE_TDSC within a new java project. 
Current code is specified to run the program under localhost. For operating in the network-mode, uncomment the line "Socket socket = new Socket("193.1.132.81", PORT);" and specify the correct IP address of the terminal running the Client.java file.
This is a typical TCP client-server application. 
Specify the Common_RSA_Certificate_Path to a known location.
Uncomment the following:
    RSA_generate_keys(Common_RSA_Certificate_Path, Entity_AS);
    RSA_generate_keys(Common_RSA_Certificate_Path, Entity_C);
Run the AuthenticationServer file once to generate the RSA keys to the path specified above.
Then comment those two lines.

First Run the AuthenticationServer.java file and wait till the SERVER READY dialogue appear in the CLI.
Then Run the Client.java file.

Observe the outputs of each stage in the CLI.
