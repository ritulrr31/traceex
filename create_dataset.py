import pandas as pd
import numpy as np

np.random.seed(42)

N = 2000

data = pd.DataFrame({
    "duration": np.random.exponential(10, N),
    "src_bytes": np.random.randint(100, 50000, N),
    "dst_bytes": np.random.randint(100, 100000, N),
    "packets": np.random.randint(1, 500, N),
    "src_port": np.random.randint(1024, 65535, N),
    "dst_port": np.random.choice(
        [20, 21, 22, 23, 25, 53, 80, 110, 443, 8080],
        N
    ),
    "protocol": np.random.choice(
        ["TCP", "UDP", "ICMP"],
        N
    ),
    "tcp_flags": np.random.choice(
        ["SYN", "ACK", "FIN", "PSH", "RST"],
        N
    ),
    "direction": np.random.choice(
        ["forward", "backward"],
        N
    )
})

data["label"] = np.random.choice(
    ["normal", "attack"],
    N,
    p=[0.75, 0.25]
)

data.to_csv(
    "../data/network_flows.csv",
    index=False
)

print("Synthetic dataset created successfully!")
print("Rows:", len(data))
print("Location: ../data/network_flows.csv")
print(data.head())