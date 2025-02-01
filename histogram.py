import sys
import matplotlib.pyplot as plt

def generate_histogram(packet_sizes):
    # Plot the histogram of packet sizes
    plt.hist(packet_sizes, bins=20, edgecolor='black')  # Adjust bins as necessary
    plt.title("Distribution of Packet Sizes")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.grid(True)

    # Save the histogram as an image file
    plt.savefig("packet_size_histogram.png")
    plt.close()

if __name__ == "__main__":
    # Get packet sizes from the command-line arguments
    packet_sizes = [int(size) for size in sys.argv[1:]]
    generate_histogram(packet_sizes)
