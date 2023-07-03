import hashcat

print("##############################")
print("# Hashcat Controller Example #")
print("##############################\n")

print("  This script will run 2 separate hashcat jobs and")
print("  show the results of both once they are done")
print("    1) A straight wordlist attack")
print("    2) A brute force attack with a mask\n")

# Create controller
hc = hashcat.HashcatController("/usr/bin/hashcat")

# Setup first job
hc.set_hashlist("data/example.0")
hc.set_hash_type(hashcat.HashMode.md5)
hc.set_attack(hashcat.AttackMode.straight, wordlist="data/wordlist.txt")

# Run first job
print("Starting first job")
print(f"Full command:\n{hc.get_command()}")
pid = hc.run()
print(f"Running with pid {pid}...", end="", flush=True)
hc.wait()
print(" Done\n")

# Setup second job
# The hashlist and hash type remain the same, so the only thing that needs to
# change is the attack type
hc.set_attack(hashcat.AttackMode.brute_force, mask="Spring?d?d")

# Run second job
print("Starting second job")
print(f"Full command:\n{hc.get_command()}")
pid = hc.run()
print(f"Running with pid {pid}...", end="", flush=True)
hc.wait()
print(" Done\n")

# Show the results
found = hc.show()
not_found = hc.left()

print("Cracked:")
for result in found:
    print(f"  {result}")
print()
print("Not cracked:")
for result in not_found:
    print(f"  {result}")
print()

