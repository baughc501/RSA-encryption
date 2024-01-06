"""
    Team Members:
    Jared Bratton
    Chris Baugh
    Cameron Holbrook

    CSCI 3330 Project 1 
    RSA: An asymmetric cryptosystem for cybersecurity

"""

# Random prime number generator 
import random

def get_rand_prime():
    primefound = False
    while primefound == False:
        rand_prime = random.randint(100000, 1000000)
        primefound = primeTest(rand_prime) 
                     
    return rand_prime

# Fermat's Test(code from class)
def primeTest(p):
    if (p % 2) == 0: # To eliminate even numbers quickly
        return False
    else:
        for i in range(1, 20): #Number of runs in fermat test
            for i in range(1, p):
                if pow(i, p-1, p) != 1:
                    return False
                    break      
        return True

# Creates the keys with one call from main()
def generate_keys():
    p = get_rand_prime()    # Find p, q
    q = get_rand_prime()
    n = (p * q)             # calculate n
    phi = (p - 1) * (q-1)   # calculate phi
    e = random.randint(1, phi) #Find e
    k = gcd(e, phi)
    while k != 1: # Apply Euclid gcd until e is found
        e = random.randint(1, phi)
        k = gcd(e, phi)     
    d, y, x = extended_gcd(e, phi) # find d using extended Euclid's
    if (d == e):
        (x, y, d) = extended_gcd(e, phi)    
    d = d % phi 
    if (d < 0): #prevent d from being negative
        d += phi          
    return ((e , n),(d , n)) # return both keys


# Applies Euclid's gcd algorithm (code from class)
# Finds the gcd of (e , phi)
def gcd(a=1, b=1):
    if b == 0:
        return a
    else:
        return gcd(b, a%b)
    

# Applies extended Euclid's gcd algorithm (code from class)
# Calculates 'd' by finding the inverse of 'e'    
def extended_gcd(a, b):
    if b == 0:
        return (a, 0, 1)
    (x, y, d) = extended_gcd(b, a%b)
    return y, x - a//b*y, d

                     
# Encrypts the message using Python's fast exponentiation algorithm.
# Encrytion formula C = M^e mod n
# Each character is converted to an int for calculations """ 
def encryptMessage(public_key):
    e, n = public_key
    message = input("Enter a message: ")
    encryptedMessage = [pow(ord(chr), e, n) for chr in message]
        
    return encryptedMessage


# Decrypts the message using Python's fast exponentiation algorithm.
# Decrytion formula M = C^d mod n
# Each int is converted back to a chr after calculations 
def decryptMessage(encryptedMessagesArray, index, private_key):
    d, n = private_key
    temp = encryptedMessagesArray[int(index) - 1 ]
    decryptedMessage = [chr(pow(i, d, n)) for i in temp]
    return "".join(decryptedMessage)


# Manages the message decryption process for the owner 
def handleDecryptMessage(encryptedMessagesArray, private_key):
    if len(encryptedMessagesArray) == 0:
        print("There are no messages to decrypt.")
        print()
        return 
    elif len(encryptedMessagesArray) >= 1:
        # Print the encrypted message's lengths to choose from.
        print("The following messages are avaible:")
        for index, encryptedMessage in enumerate(encryptedMessagesArray):
            print("\t", index + 1, ". (length: ", len(encryptedMessage), ")", sep="") 
        # Take user input to choose a message to decrypt.
        decryptMessageChoice = input("Enter your choice: ")
        # Call to decrypt the message.
        decryptedMessage = decryptMessage(encryptedMessagesArray, decryptMessageChoice, private_key)
        decryptedMessage = decryptedMessage.upper()
        print("Decrypted message: ", decryptedMessage)
        print()
        return decryptedMessage


# Manages the message authentication process for the public user
def handleAuthenticateMessage(signaturesArray, unencryptedMessagesArray, public_key):
    if len(unencryptedMessagesArray) == 0:
        print("There are no signatures to authenticate.")
        print()
        return
    elif len(unencryptedMessagesArray) >= 1:
        print("The following messages are avaible:")
        for index, unencryptedMessage in enumerate(unencryptedMessagesArray):
            print("\t", index + 1, ". ", unencryptedMessage, sep="")
        print()    
        unencryptMessageChoice = input("Enter your choice: ")
        authenticateMessage(signaturesArray, unencryptedMessagesArray, unencryptMessageChoice, public_key)
        return unencryptMessageChoice
        

# Authenticates an owner encrypted signature by applying the public key
# Once unencrypted, the computed string is compared to original string 
def authenticateMessage(signaturesArray, unencryptedMessagesArray, unencryptMessageChoice, public_key):
    e, n = public_key
    temp = signaturesArray[int(unencryptMessageChoice) - 1 ]
    decryptedMessage = [chr(pow(i, e, n)) for i in temp]
    decryptedMessage ="".join(decryptedMessage)
    if decryptedMessage == unencryptedMessagesArray[int(unencryptMessageChoice) - 1]:
        print("Signature is valid.")
        print()
    else:
        print("Warning: Invalid signature.")
        print()
        
        
# Signs the message using Python's fast exponentiation algorithm.
# Encrypts the signature using formula M = C^d mod n
def digitallySignMessage(messageToSign, private_key):
    d, n = private_key
    signature = [pow(ord(chr), d, n) for chr in messageToSign] 
    return signature
    

def main():
    
    # Variables  
    encryptedMessagesArray = [] #Holds encrypted messages from public user
    unencryptedMessagesArray= [] #Holds original plaintext signatures from owner
    signaturesArray = [] #Holds encrypted signatures from owner
    outerLoop = True
    innerLoop = True
    
    print()
    print("Please wait while the keys are generated....")
    print()
    
    # Call to generate the keys.
    # Return format: public_key (e,n), private_key (d,n)
    public_key, private_key = generate_keys() 
    print("RSA keys have been generated.")
    print()    
    while outerLoop:
        
        # Need to refresh this every loop.
        outerLoop = True
        innerLoop = True
        
        # Print outer menu.
        print("Please select your user type:",
              "\t1. A public user",
              "\t2. The owner of the keys.",
              "\t3. Exit program", sep="\n")
        firstChoice = input("Enter your choice: ")
        
        print()
        
        
        
        ################################################### Public user choice.
        if firstChoice == "1":
            
            while(innerLoop):
                
                # Print inner menu for public user.
                print("As a public user, what would you like to do?",
                      "\t1. Send an encrypted message",
                      "\t2. Authenticate a digital signature",
                      "\t3. Exit", sep="\n")
                secondChoice = input("Enter your choice: ")
                print()
                
                                
                # Public user commands.
                if secondChoice == "1":
                    encryptedMessagesArray.append(encryptMessage(public_key))        
                    print("Message encrypted and sent.")
                    print()
                    
                elif secondChoice == "2":
                    handleAuthenticateMessage(signaturesArray, unencryptedMessagesArray, public_key)
                
                elif secondChoice == "3":
                    innerLoop = False
        
        
        
        #################################################### Owner user choice.
        if firstChoice == "2":
            
            while(innerLoop):
                
                # Print inner menu for owner user.
                print("As the owner of the keys, what would you like to do?",
                      "\t1. Decrypt a received message",
                      "\t2. Digitally sign a message",
                      "\t3. Exit", sep="\n")
                secondChoice = input("Enter your choice: ")
                print()
                
                
                
                # Determine owner command.
                if secondChoice == "1":
                    handleDecryptMessage(encryptedMessagesArray, private_key)
                    
                elif secondChoice == "2":
                    messageToSign = input("Sign your message: ")
                    unencryptedMessagesArray.append(messageToSign)
                    signaturesArray.append(digitallySignMessage(messageToSign, private_key))
                    
                    print("Message signed and sent.")
                    print()
                
                elif secondChoice == "3":
                    innerLoop = False
            
            
        ################################################################# Exit.
        elif firstChoice == "3":
            print("Bye for now!")
            outerLoop = False
        
        print()

if __name__ == "__main__":
    main()
    