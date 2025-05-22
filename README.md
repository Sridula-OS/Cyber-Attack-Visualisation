# Cyber-Attack-Visualisation
**_Overview_**

This project leverages graph theory to detect and analyze cybersecurity attacks in modern computer networks. As cyber threats become increasingly sophisticated, traditional detection methods often struggle to keep pace. By modeling networks as graphs—where nodes represent devices or hosts and edges represent traffic flows—this approach provides a structural and scalable way to monitor, detect, and respond to a wide range of network attacks.


**_Key Features_**

* Attack Detection: Identifies various cyberattacks such as Denial of Service (DoS), Distributed Denial of Service (DDoS), SSH brute force, Man-in-the-Middle (MitM), ARP spoofing, data exfiltration, and DNS tunneling.

* Graph Modeling: Represents network communication as graphs to analyze patterns, connectivity, centrality, and path anomalies.

* Interpretability: Provides clear insights into network behavior and attack propagation using well-established graph theory concepts.

* Educational Value: Designed to be accessible and informative for students, educators, and researchers interested in cybersecurity and graph theory.

* Learning Aid: Helps users understand both fundamental and advanced concepts in network security and graph-based data analysis through practical implementation.

* Great Visualization: Features powerful and intuitive graph visualizations, making it easier to interpret network structures, identify anomalies, and trace attack paths.


**_How It Works_**

* Graph Construction: Network traffic is captured and transformed into a graph structure.

* Analysis Techniques: Utilizes centrality measures, connectivity checks, path analysis, and subgraph detection to identify deviations from normal behavior.

* Attack Indicators:

   Sudden increase in connections to a single node may indicate DoS/DDoS.

   Unexpected changes in shortest paths or edge structures may signal MitM or ARP spoofing.

   Weighted edge analysis helps detect data exfiltration and DNS tunneling.

   Clustering algorithms isolate botnet activity in DDoS scenarios.

* Visualization: Graph-based visualizations help security analysts and learners interpret and trace attack vectors, making complex network data more understandable and engaging.

**_Getting Started_**

Follow these steps to set up and run the project:

1. Clone the repository

Clone this repository to your local machine using:
```bash
git clone <repository_url>
```
2. Install required dependencies

Ensure you have Python installed. Install all necessary Python packages using:
```bash
pip install <library_name>
```
Run the Python script

3. Execute the main Python file to process the network data. This will generate a JSON file containing the graph data:

```bash
python main.py
```
(Replace main.py with the actual script name if different.)

4. Visualize the graph

Open the HTML visualization file (e.g., index.html) in your code editor.

Use a live server extension (such as "Live Server" in Visual Studio Code) to launch the HTML file in your browser.

The visualization will read the generated JSON file and display the network graph.

Tip: To use Live Server in VS Code, right-click the HTML file and select "Open with Live Server."
