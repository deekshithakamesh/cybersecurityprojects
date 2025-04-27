import itertools
import string
import time

def attempt_password(target_password, max_length=8, verbose=False):
    """
    Attempt to crack a password using brute force.
    For educational purposes only.
    
    Args:
        target_password: The password to crack
        max_length: Maximum password length to try
        verbose: Whether to print progress information
    
    Returns:
        tuple: (cracked password, time taken, attempts made)
    """
    charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    start_time = time.time()
    attempts = 0
    
    for length in range(1, max_length + 1):
        if verbose:
            print(f"Trying passwords of length {length}...")
        
        for guess in itertools.product(charset, repeat=length):
            password_guess = ''.join(guess)
            attempts += 1
            
            if verbose and attempts % 100000 == 0:
                print(f"Attempts: {attempts}, Current guess: {password_guess}")
            
            if password_guess == target_password:
                end_time = time.time()
                time_taken = end_time - start_time
                return password_guess, time_taken, attempts
    
    return None, time.time() - start_time, attempts

def main():
    # Ask for password input directly from the user
    target_password = input("Enter the password to crack: ")
    max_length = int(input("Enter maximum password length to try (default 8): ") or "8")
    verbose = input("Show progress details? (y/n): ").lower() == 'y'
    
    print("\nEducational Password Cracker")
    print("---------------------------")
    print(f"Target password length: {len(target_password)}")
    print(f"Maximum search length: {max_length}")
    print("Starting brute force attack...")
    
    result, time_taken, attempts = attempt_password(
        target_password, 
        max_length=max_length,
        verbose=verbose
    )
    
    print("\nResults:")
    print(f"Attempts made: {attempts}")
    print(f"Time taken: {time_taken:.2f} seconds")
    
    if result:
        print(f"Password cracked: '{result}'")
        print(f"Average attempts per second: {attempts / time_taken:.2f}")
    else:
        print("Password not found within the specified constraints.")

if __name__ == "__main__":
    main()