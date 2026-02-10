-- ================================
-- MEMBER 1: AUTHENTICATION & USERS
-- ================================

CREATE TABLE users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    full_name VARCHAR(100) NOT NULL,
    phone_number VARCHAR(20) UNIQUE NOT NULL,
    sim_number VARCHAR(20) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    pin_hash VARCHAR(255) NOT NULL,
    pin_salt VARCHAR(255) NOT NULL,
    balance DECIMAL(10,2) DEFAULT 0 CHECK (balance >= 0),
    account_status ENUM('active','suspended','locked') DEFAULT 'active',
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    is_two_factor_enabled BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    user_id INT NOT NULL,
    session_token VARCHAR(512) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE trusted_devices (
    device_id VARCHAR(255) PRIMARY KEY,
    user_id INT NOT NULL,
    device_name VARCHAR(100),
    device_fingerprint TEXT NOT NULL,
    trusted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE two_factor_codes (
    code_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    code_type ENUM('login','transaction','pin_reset'),
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE pin_history (
    pin_history_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    old_pin_hash VARCHAR(255),
    new_pin_hash VARCHAR(255),
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Trigger: log PIN changes
DELIMITER $$
CREATE TRIGGER after_pin_change
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    IF OLD.pin_hash != NEW.pin_hash THEN
        INSERT INTO pin_history(user_id, old_pin_hash, new_pin_hash)
        VALUES (NEW.user_id, OLD.pin_hash, NEW.pin_hash);
    END IF;
END$$
DELIMITER ;

-- Procedure: failed login handling
DELIMITER $$
CREATE PROCEDURE log_failed_login(IN p_user_id INT)
BEGIN
    UPDATE users
    SET failed_login_attempts = failed_login_attempts + 1
    WHERE user_id = p_user_id;

    IF (SELECT failed_login_attempts FROM users WHERE user_id = p_user_id) >= 3 THEN
        UPDATE users
        SET account_status = 'locked',
            locked_until = DATE_ADD(NOW(), INTERVAL 5 MINUTE)
        WHERE user_id = p_user_id;
    END IF;
END$$
DELIMITER ;
