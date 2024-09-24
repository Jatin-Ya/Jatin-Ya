
# CAABAC Algorithms and Mathematical Explanation

This README provides detailed steps and mathematical explanations for all six algorithms in the **Context-Aware Attribute-Based Access Control (CAABAC)** scheme. These algorithms outline how the system initializes, generates keys, encrypts data, and decrypts data while incorporating context-aware attributes.

---

## **Algorithm 1: System Initialization**

**Purpose**: Set up the system's public parameters and master keys. Generate secret keys for contextual parameters.

### **Steps**:

1. **Select Bilinear Groups**:
   - Choose a bilinear group `G_1` of prime order `q` with generator `g`.
   - Define a bilinear map `e: G_1 × G_1 → G_2`.

2. **Define Hash Functions**:
   - `H_1: {0,1}* → G_1` (a hash function mapping strings to elements in `G_1`).
   - `H_2: G_2 → ℤ_q*` (a hash function mapping elements in `G_2` to integers modulo `q`).

3. **Attribute Authority (AA) Key Generation**:
   - AA randomly selects `α_1, β ∈ ℤ_q`.
   - Computes `h = g^β`.
   - Public key: `PK_AA = { G_1, h, g, e(g, g)^α_1 }`.
   - Master key: `MK_AA = { α_1, β }`.

4. **Key Generation Center (KGC) Key Generation**:
   - KGC randomly selects `α_2 ∈ ℤ_q`.
   - Computes `PK_KGC = e(g, g)^α_2`.
   - Master key: `MK_KGC = { α_2 }`.

5. **System Public Parameters**:
   - Compute `α = α_1 + α_2`.
   - Publish public parameters `PK = { G_1, h, g, e(g, g)^α }`.
   - Keep `MK = { MK_AA, MK_KGC }` secret.

6. **Context Manager (CM) Key Generation**:
   - For each contextual parameter `c_j`, CM selects a secret `δ_cj ∈ ℤ_q`.
   - Computes `γ_cj = g^δ_cj`.
   - Defines public keys `PK_cj = { F_cj, γ_cj }`.

---

## **Algorithm 2: Key Generation (Key Commitment Protocol)**

**Purpose**: Generate a user's private key collaboratively between AA and KGC to prevent key escrow.

### **Steps**:

1. **KGC's Initial Computation**:
   - Randomly select `τ ∈ ℤ_q`.
   - Compute `V = g^((αβ) / τ)`.
   - Send `V` and proof of knowledge `PoK(τ, X)` to AA.

2. **AA's Computation**:
   - Randomly select `τ_1 ∈ ℤ_q`.
   - Compute `V_1 = V^(τ_1 / β)`, `X_1 = h^(rτ_1)`.
   - Send `V_1`, `X_1`, and `PoK(τ_1, β, r)` to KGC.

3. **KGC's Further Computation**:
   - Randomly select `τ_2 ∈ ℤ_q`.
   - Compute `V_2 = (V^(τ_1) · X_1)^τ_2`.
   - Send `V_2` and `PoK(τ_2)` to AA.

4. **AA's Final Computation**:
   - Compute `V_3 = V_2^(1 / τ_1)`.
   - Send `V_3` and `PoK(τ_1)` to KGC.

5. **KGC's Key Generation**:
   - Compute partial secret key `D = V_3^(1 / τ_2)`.
   - Send `D` to the user.

6. **AA's Key Generation for User's Attributes**:
   - Compute `D_i = H_1(att_i)^r`, and `L = g^r`.
   - Send `{ D_i, L }` to the user.

7. **User's Private Key**:
   - User's private key `SK_u = { D = g^α h^r, L = g^r, D_i = H_1(att_i)^r }`.

---

## **Algorithm 3: Encryption**

**Purpose**: Encrypt data under an access policy `T` that includes both attributes and contextual conditions.

### **Steps**:

1. **Access Tree Polynomials**:
   - For each node `x` in the access tree `T`, define a polynomial `q_x` of degree `d_x = k_x - 1`.
   - For the root node `R`, set `q_R(0) = s` (a random secret).
   - For other nodes, set `q_x(0) = q_parent(x)(index(x))`.

2. **Contextual Token Generation**:
   - For each contextual node `x` associated with parameter `c_j`, randomly select `r_cj ∈ ℤ_q`.
   - Compute `A_x^cj = g^r_cj`, `B_x^cj = q_x(0) + H_2(e(H_1(F_cj), γ_cj)^r_cj)`.

3. **Ciphertext Components**:
   - Compute `~C = K_s · e(g, g)^(αs)`, where `K_s` is a symmetric key.
   - Compute `C = g^s`.
   - For each node `x` (attribute or contextual node), compute:
     - `C_x = h^(q_x(0))`.
     - `C'_x = H_1(att_x)^(-s)` (for attribute nodes).

4. **Final Ciphertext**:
   - Ciphertext `CT` includes `T`, `~C`, `C`, `C_x`, `C'_x`, and contextual tokens `T_x^cj = { A_x^cj, B_x^cj }`.

5. **Signature for Integrity**:
   - Compute `σ = H_1(K_s)^γ_GW`.

---

## **Algorithm 4: Decryption**

**Purpose**: Allow users to decrypt the ciphertext if their attributes and contextual tokens satisfy the access policy.

### **Steps**:

1. **Obtain Access Tokens**:
   - User requests access tokens `AT_x^cj` from CM for required contextual parameters.
   - CM verifies the context and provides `AT_x^cj = H_1(F_cj)^δ_cj`.

2. **Recursive Node Decryption Function**:
   - For leaf nodes, compute `F_x = e(C'_x · C_x, L) · e(C, D_i)`.
   - For contextual nodes, compute `F_x = e(h · C'_x, L) · e(C, D_i)^(T_x^cj')`.

3. **Reconstruct Secret at Root**:
   - Use recursive Lagrange interpolation to reconstruct the secret `A = e(g, g)^(rβs)` at the root.

4. **Recover Symmetric Key**:
   - Compute `K_s' = ~C · (A / e(C, D))^(-1)`.

5. **Verify Signature and Decrypt**:
   - Check if `e(σ, g) = e(H_1(K_s'), g^γ_GW)`.

---

## **Algorithm 5: Extended CAABAC Encryption**

**Purpose**: Allow contextual tokens to be appended to arbitrary nodes (not just leaf nodes) in the access tree for more complex policies.

### **Steps**:

1. **Access Tree Modification**:
   - For each node `x`, associate two values `q_x^0` and `q_x^1`.

2. **Secret Sharing**:
   - For the root node `R`, set `q_R^0 = s`.
   - For each node `x`, compute `q_x^1` based on whether `x` is associated with contextual parameters.
   - If `x` has contextual parameters `c_j`, select random `s_cj^x` and set `q_x^1 = q_x^0 - ∑_j s_cj^x`.

3. **Polynomial Construction**:
   - For each node `x`, construct polynomial `q_x` with `q_x(0) = q_x^1`.

4. **Contextual Token Generation**:
   - For each contextual parameter `c_j`, compute `A_x^cj = g^r_cj`, `B_x^cj = s_cj^x + H_2(e(H_1(F_cj), γ_cj)^r_cj)`.

5. **Ciphertext Components**:
   - Compute `~C = K_s · e(g, g)^(αs)`.
   - Compute `C = g^s`.
   - For each node `x`, compute `C_x = h^(q_x^1)`, `C'_x = H_1(att_x)^(-s)`.

6. **Final Ciphertext**:
   - Include all components and contextual tokens in `CT`.

---

## **Algorithm 6: Extended CAABAC Decryption**

**Purpose**: Decrypt ciphertexts where contextual tokens are appended to arbitrary nodes.

### **Steps**:

1. **Obtain Access Tokens**:
   - Obtain `AT_x^cj

` for the required contextual parameters.

2. **Recursive Node Decryption Function**:
   - For leaf and contextual nodes, compute values as in Algorithm 4.

3. **Reconstruct Secret at Root**:
   - Combine child nodes' values and recover the secret `A = e(g, g)^(rβs)`.

4. **Recover Symmetric Key and Decrypt**:
   - Proceed as in Algorithm 4.


