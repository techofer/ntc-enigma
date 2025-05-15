# NTC-Enigma

This repository contains a Python-based framework to modify network traffic datasets (PCAP files) through occlusion techniques and protocol analysis. The framework is based on the research paper:

> **"SoK: Decoding the Enigma of Encrypted Network Traffic Classifiers"**\
> *Nimesha Wickramasinghe, Arash Shaghaghi, Gene Tsudik, Sanjay Jha*\
> *2025 IEEE Symposium on Security and Privacy (SP)*\
> [Read it on CSDL](https://www.computer.org/csdl/proceedings-article/sp/2025/223600b732/26hiUvcHgly) | [Read it on ArXiv](https://arxiv.org/abs/2503.20093)

## 📌 Overview
NTC-Enigma enables a systematic analysis of machine learning-based approaches to network traffic classification (NTC) in the context of modern encryption protocols. It also identifies overfitting caused by various design choices, and examines the validity of assumptions underlying NTC models.

## 📂 Repository Structure

```
📁 NTC-Enigma/
├── traffic_occlusion/
│   ├── main.py
│   ├── occluder.py
│   ├── README.md
│   └── util.py
│   LICENSE
└── README.md
```

### [traffic_occlusion](https://github.com/nime-sha256/ntc-enigma/tree/main/traffic_occlusion)
This directory provides a set of Python tools to apply occlusion techniques to PCAP files. These techniques mask, modify, or randomize different traffic attributes to protect sensitive information while preserving the structure and properties of the traffic.

For detailed usage instructions, refer to [traffic_occlusion/README.md](https://github.com/nime-sha256/ntc-enigma/blob/main/traffic_occlusion/README.md).

## 🤝 Contribution

Feel free to **fork**, **contribute**, and **open issues** for improvements! For major changes, please open an issue first to discuss your ideas.

## 📜 Citation

If you find this work useful, please consider citing our paper:

```bibtex
@INPROCEEDINGS {,
  author = { Wickramasinghe, Nimesha and Shaghaghi, Arash and Tsudik, Gene and Jha, Sanjay },
  booktitle = { 2025 IEEE Symposium on Security and Privacy (SP) },
  title = {{ SoK: Decoding the Enigma of Encrypted Network Traffic Classifiers }},
  year = {2025},
  ISSN = {2375-1207},
  pages = {1825-1843},
  doi = {10.1109/SP61157.2025.00165},
  url = {https://doi.ieeecomputersociety.org/10.1109/SP61157.2025.00165},
  publisher = {IEEE Computer Society},
  address = {Los Alamitos, CA, USA},
  month = {May}
}
```

## 📜 License

This project is licensed under the **MIT License**.

---

For questions or suggestions, contact:

- **Nimesha Wickramasinghe** - [*n.wickramasinghe@unsw.edu.au*](mailto\:n.wickramasinghe@unsw.edu.au)
- **Arash Shaghaghi** - [*a.shaghaghi@unsw.edu.au*](mailto\:a.shaghaghi@unsw.edu.au)
