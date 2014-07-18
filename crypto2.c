/* Code by Michael Hughes */

// ================
// Class inclusions
// ===================
   #include <stdlib.h>
   #include <stdio.h>
   #include <math.h>
   #include <fcntl.h>
   #include <errno.h>
   #include <string.h>
   #include <unistd.h>
 
// ===================

// ============
// Struct qAndK
// =============
   struct qAndK{
        
       int k; // Variable to hold k
       int q; // Variable to hold q

   } qkVals; // End struct qAndK
// =============================

// =================
// Function findQVal
// ====================
   void findQVal(unsigned long long n){

       int k = 0; // Variable to increment to find k

       while((n%2) == 0){ // While n not odd
           n = n/2; 
           k++;
       } // While n not odd

       qkVals.q = n; // Set q value
       qkVals.k = k; // Set k value
   
   } // End findQVal
// =================

// ==================
// Function sqAndMult
// =============================================================================================
   unsigned long long sqAndMult(unsigned long long a,unsigned long long b,unsigned long long n){

       int bVal[32];// Variable to hold binary value
       int flag = 0;// Variable to hold flag (Used to determine if 0 are need for binary number)
       int i;       // Varaible to increment
       int k = 0;   // Variable to hold count
       unsigned long long f = 1; // Variable to hold mod expo

       for(i=0; i < 32; i++){ // For get Binary
           bVal[i] = ((b>>i)&1);
       } // End for get Binary

       for(i=31; i >= 0; i--){ // For determine count of binary values
           
           if(bVal[i] == 1 || flag == 1){ // If value needs to be counted
               flag = 1;// Set flag
               k++;     // Increment count
           } // End if value needs to be counted
       } // End for determine count of binary values

       for(i = k; i > 0; i--){ // For mod expo
           f = (f*f)%n; // Get new f
   
           if((bVal[i-1]) == 1){ // If b == 1
               f = (f*a)%n; // Get new f

           } // End if b == 1
       } // End for mod expo
       
       return f; // Return mod expo

   } // End sqAndMult
// ==================

// ====================
// Function millerRabin
// ======================================
   int millerRabin(unsigned long long p){

       int j;                     // Variable to increment
       unsigned long long a = 1;  // Variable to hold a value
       unsigned long long k;      // Variable to hold k value
       unsigned long long q;      // Variable to hold q value
       unsigned long long val = 2;// Variable to holdl powers of 2
       

       findQVal(p-1);// Calculate Q and K value
       k = qkVals.k; // Get k value
       q = qkVals.q; // Get q value

       if(p < 2){ // If p < 2
           return 1;
       } // End if p < 2
       while(a <= 1){ // While get random a val   
           a = arc4random()%(p-1);
       } // End while get random a val
       if(sqAndMult(a, q, p) == 1){ // If prime return 0
           return 0;
       } // End if prime return 0
       for(j=0; j < (k-1); j++){ // For check for prime
           val << (j-1);
           if(sqAndMult(a, (val*q), p) == (p-1)){ // If prime return 0
               return 0;
           } // End if prime return 0
           val = 2; // Reset val
       } // End for check for prime
      
       return 1; // Return composite
   
   } // End millerRabin
// ====================

// =================
// Function getPrime
// ==============================
   unsigned long long getPrime(){

       unsigned int seed;
       unsigned long long p = 2; // Variable to hold potential prime number
       
       printf("Enter a seed value: \n");
       scanf("%d", &seed); // Get seed value
       
       while((p%2) == 0){ // While p even
           p =(unsigned long long) arc4random(); // Get random number

           if(((p>>31)&1) != 1){ // If set 32nd bit
               p = p|(1<<31);
           }// End if set 32nd bit
       } // End while p even
       
       while(millerRabin(p) != 0){ // While find prime
           
           p = (unsigned long long)arc4random(); // Get random number
          if(((p>>31)&1) != 1){ // If set 32nd bit
                   p = p|(1<<31);
          }// End if set 32nd bit

           while((p%2) == 0){ // While p even
               p = (unsigned long long)arc4random(); // Get random number

               if(((p>>31)&1) != 1){ // If set 32nd bit
                   p = p|(1<<31);
               }// End if set 32nd bit
           } // End while p even
       } // While find prime 

       return p; // Return prime number 

   } // End getPrime
// =================

// ===============
// Function keyGen
// =============
   int keyGen(){

       FILE * pubFd;        // File descriptor for public key file
       FILE * priFd;        // File descriptor for private key file
       unsigned long long d = 0;  // Variable to hold private key
       unsigned long long e2;     // Variable to hold generator
       unsigned long long e1 = 2; // Variable to hold primitive root
       unsigned long long p;      // Variable to hold large prime number
  
       pubFd = fopen ("pubkey.txt","w"); // Open public key file
       priFd = fopen ("prikey.txt","w"); // Open private key file
   
       if(pubFd < 0 || priFd < 0){ // If open error
           fprintf(stderr, "Error opening pubkey.txt or prikey.txt: %s", strerror(errno));
           return 1;
       } // End if open error

       p = getPrime(); // Get large prime number

       while(d < 1){ // While d < 1
           d = (unsigned long long)arc4random()%(p-2); // Get private key
       } // End while d < 1
       
       e2 = sqAndMult(e1, d, p); // Compute e2

       fprintf (pubFd, "%llu, %llu, %llu\n",p, e1, e2); // Write public key to file
       fprintf (priFd, "%llu, %llu, %llu\n",p, e1, d);  // Write private key to file
       
       fclose(pubFd); // Close pubFd
       fclose(priFd); // Close priFd

       return 0;     // End without error

   } // End function keyGen
// ========================

// ===================
// Function encryption
// =================
   int encryption(){

       int rd;            // Variable to determine how much data was read
       int ptextFd = 0;   // File descriptor for plain text
       FILE * ctextFd = 0; // File descriptor for cipher text
       FILE * keyFd;       // File descriptor for public key file
       unsigned long long int c1;// Variable to hold cipher text
       unsigned long long c2;    // Variable to hold cipher text
       unsigned long long e1;    // Variable to hold public key
       unsigned long long e2;    // Variable to hold generator
       unsigned long long p;     // Variable to hold large prime
       unsigned long long r = 0; // Variable to hold random in in 1 to p-1
       unsigned char pData[4];   // Variable to hold plaintext
       unsigned long long P;     // Variable to hold integer rep of plaintext
       char data[30];
       
       keyFd   = fopen ("pubkey.txt","r");    // Open public key file  
       ctextFd = fopen ("ctext.txt","w");     // Open cipher text for writing
       ptextFd = open("ptext.txt", O_RDONLY); // Open plain text for reading
   
       if(keyFd < 0 || ptextFd < 0 || ctextFd < 0){ // If open error
           fprintf(stderr, "Error opening pubkey.txt, ctext.txt or ptext.txt: %s", strerror(errno));
           return 1;
       } // End if open error

       fgets ( data, sizeof(data), keyFd);       // Get keys from file
       sscanf(data,"%llu, %llu, %llu\n",&p, &e1, &e2); // Parse out keys
      
       while((rd = read(ptextFd, pData, 4)) != 0){ // While read data
       
           P = (pData[0] << 24) | (pData[1] << 16) | (pData[2] << 8) | pData[3]; //Put char data in 32_int
    
           while(r < 1){ // While get r > 1
               r = arc4random()%(p-1); // Get random r
           } // End while get r > 1
          
         //  r = 1;
           c1 = sqAndMult(e1, r, p);  // Calculate C1
           c2 = (( P)*(sqAndMult(e2, r, p)))%p; // Encrypt plain text to C2

           fprintf (ctextFd, "%llu, %llu\n",c1, c2); // Write cipher text to file

           r = 0; // Reset r for next run
           for(int i = 0; i < 4; i++){ // For reset P
               pData[i] = 0;
           } // End for reset P
       } // End while read data 

       close(ptextFd);  // Close plain text file
       fclose(ctextFd); // Close cipher text file
       fclose(keyFd);   // Close key file
      
       return 0; // Return without error

   } // End function encryption
// ============================

// ===================
// Function decryption
// =================
   int decryption(){

       FILE * ctextFd;  // File descriptor for cipher text
       FILE * keyFd;    // File descriptor for public key file
       int dtextFd;     // File descriptor for plain text
       char data[30];   // Buffer for cipher file reading
       char pData[4];   // Buffer for plain text
       unsigned long long e1; // Variable to hold generator
       unsigned long long c1; // Variable to hold cipher text 1
       unsigned long long c2; // Variable to hold cipher text 2
       unsigned long long d;  // Variable to hold private key
       unsigned long long p;  // Variable to hold prime number
       unsigned long long P;  // Variable to hold plaintext
      

       keyFd   = fopen ("prikey.txt","r");    // Open private key file
       ctextFd = fopen("ctext.txt", "r"); // Open plain text for reading
       dtextFd = open("dtext.txt", O_WRONLY|O_CREAT|O_TRUNC, S_IWUSR|S_IRWXU|S_IWGRP|S_IRWXG); // Open c
       
       if(keyFd < 0 || dtextFd < 0 || ctextFd < 0){ // If open ecrror
           fprintf(stderr, "Error opening ptext.txt, plaintext.txt or prikey.txt: %s\n", strerror(errno));
           return 1;
       } // End if open error

       fgets ( data, sizeof(data), keyFd);// Get keys from file
       sscanf(data,"%llu, %llu, %llu\n",&p, &e1, &d); // Parse out keys

       while(fgets ( data, sizeof(data), ctextFd) != NULL){ // While lines to read

           sscanf(data,"%llu, %llu\n",&c1, &c2); // Parse out keys

           P = ((c2)*(sqAndMult(c1, (p-1-d), p)))%p; // Calculate the plain text

           pData[3] = P & 0xFF;       // Seperate first byte
           pData[2] = (P >> 8) & 0xFF;// Seperate second byte
           pData[1] = (P >> 16)& 0xFF;// Seperate third byte
           pData[0] = (P >> 24)& 0xFF;// Seperate fourth byte

           P = 0; // Reset P

          for(int i = 0; i < 4; i++){ // For output plain text
              printf("%c",pData[i]);
          } // End for output plaintext

          write(dtextFd, pData, 4); // write plaintext to file
          
       } // End while lines to read
       printf("\n"); // Add new line just in case not in text file

       fclose(keyFd);  // Close key file
       fclose(ctextFd);// Close cipher text file
       close(dtextFd); // Close plaintext file

       return 0; // Return without error

   } // End decryption
// ===================

// =============
// Function Main
// ================================
   int main(int argv, char** argc){ 

       char selec; // Variable to hold user selection
       int err;    // Variable to determine errors
     
       printf("Plese choose one of the selections from below then hit enter:\n");
       printf("'K' for Key Generation\n");
       printf("'E' for Encryption\n");
       printf("'D' for Decrption\n");

       scanf("%c", &selec); // Get user selection

       if(selec == 'K'){ // If creating key
           err = keyGen();
       } // End if creating key
       else if(selec == 'E'){ // Else if encrypting
           err = encryption();
       } // End else if encrypting
       else if(selec == 'D'){ // Else if decrypting
           err = decryption();
       } // End else if decrypting
       else{ // Else input not recoginzed
           printf("Entry '%c' not recognized.\n", selec);
       } // End else input not recognized

       if(err == 1){ // If error
           printf("Program exited with error!\n");
           return 1;
       } // End if error
       else{ // Else no error
           return 0;
       } // Else no error 

   } // End function main
// ======================

