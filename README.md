# **PCAP Analysis - README**

## **1. Running the PCAP Analysis**
The PCAP analysis can be executed directly by running the following command in your terminal or command prompt:

```sh
python pcap_analysis.py
```

This script will:
- Load and analyze the specified **PCAP file (`0.pcap`)**.
- Extract network traffic metrics such as **total bytes transferred, packet sizes, and top source-destination pairs**.
- Answer **PCAP-specific questions** (IMS server connections, registered course, data on port 4321, and occurrences of "SuperUser").
- Generate output files containing the analysis results.

---

## **2. Generated Output Files**
Upon execution, the script will generate the following output files:

### **2.1 Text Files**
- **`pcap_analysis_results.txt`**
  - Contains the extracted **network metrics** and **PCAP-specific answers**.
- **`course_search_results.txt`**
  - Stores raw **packet data related to the keyword "course"**, allowing manual inspection.

### **2.2 Images**
- **`packet_size_distribution.png`**
  - A histogram displaying the **distribution of packet sizes** in the PCAP file.

---

## **3. Requirements**
Before running the script, ensure that **Python** and the following dependencies are installed:

```sh
pip install scapy matplotlib
```

---

## **4. Notes**
- The script assumes the **PCAP file is named `0.pcap`** and is located in the same directory.
- The **course registration data** was manually inspected from `course_search_results.txt`.
- The analysis results and images are automatically saved in the current directory.

For any issues, ensure the PCAP file exists and dependencies are installed.

---

