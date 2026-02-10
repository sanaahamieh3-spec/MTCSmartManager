-- ================================
-- MEMBER 2: TRANSACTIONS & PACKAGES
-- ================================

CREATE TABLE transactions (
    transaction_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    receipt_id VARCHAR(50) UNIQUE NOT NULL,
    user_id INT NOT NULL,
    transaction_type ENUM('transfer','recharge','package_purchase'),
    amount DECIMAL(10,2) NOT NULL,
    balance_before DECIMAL(10,2),
    balance_after DECIMAL(10,2),
    transaction_status ENUM('pending','completed','failed') DEFAULT 'pending',
    transaction_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE daily_transaction_limits (
    limit_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    transaction_date DATE NOT NULL,
    total_spent DECIMAL(10,2) DEFAULT 0,
    UNIQUE (user_id, transaction_date),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE packages (
    package_id INT PRIMARY KEY AUTO_INCREMENT,
    package_name VARCHAR(100),
    package_type ENUM('data','calls','bundle'),
    data_gb DECIMAL(10,2),
    minutes INT,
    price DECIMAL(10,2),
    validity_days INT,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE user_packages (
    user_package_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    package_id INT NOT NULL,
    expiry_date TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (package_id) REFERENCES packages(package_id)
);

-- Procedure: secure transfer
DELIMITER $$
CREATE PROCEDURE process_secure_transfer(
    IN p_user_id INT,
    IN p_amount DECIMAL(10,2)
)
BEGIN
    DECLARE v_balance DECIMAL(10,2);

    SELECT balance INTO v_balance FROM users WHERE user_id = p_user_id;

    IF v_balance >= p_amount THEN
        UPDATE users SET balance = balance - p_amount WHERE user_id = p_user_id;

        INSERT INTO transactions
        (receipt_id, user_id, transaction_type, amount, balance_before, balance_after, transaction_status)
        VALUES
        (CONCAT('TXN', UNIX_TIMESTAMP()), p_user_id, 'transfer', p_amount, v_balance, v_balance - p_amount, 'completed');
    END IF;
END$$
DELIMITER ;
