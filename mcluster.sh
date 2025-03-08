#!/bin/bash

# Get script information dynamically
SCRIPT_NAME=$(basename "$0")
INSTALL_NAME="${SCRIPT_NAME%.*}"  # Removes the .sh extension if it exists
DISPLAY_NAME="${INSTALL_NAME^^}"  # Convert to uppercase for display

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

# Install script
install() {
  install_dir="/usr/local/bin"
  if ! sudo mkdir -p "$install_dir"; then
    error "Error creating directory $install_dir. Ensure you have sudo privileges."
  fi
  install_path="$install_dir/$INSTALL_NAME"
  if ! sudo cp "$0" "$install_path" && ! sudo chmod +x "$install_path"; then
      error "Error installing $INSTALL_NAME. Ensure you have sudo privileges."
  fi
  log "$DISPLAY_NAME installed to $install_path."
}

# Uninstall script
uninstall() {
  uninstall_path="/usr/local/bin/$INSTALL_NAME"
  if [[ -f "$uninstall_path" ]]; then
    if ! sudo rm "$uninstall_path"; then
      error "Error uninstalling $INSTALL_NAME. Ensure you have sudo privileges."
    fi
    log "$DISPLAY_NAME successfully uninstalled."
  else
    warn "$DISPLAY_NAME is not installed in /usr/local/bin."
  fi
}

# Function to install Mycelium
install_mycelium() {
    log "Updating package list..."
    if ! sudo apt update; then
        error "Failed to update package list. Ensure you have sudo privileges."
    fi

    log "Installing dependencies..."
    if ! sudo apt install -y curl tar; then
        error "Failed to install dependencies. Ensure you have sudo privileges."
    fi

    log "Downloading Mycelium..."
    arch=$(uname -m)
    if [[ "$arch" == "x86_64" ]]; then
        mycelium_arch="x86_64-unknown-linux-musl"
    elif [[ "$arch" == "aarch64" ]]; then
        mycelium_arch="aarch64-unknown-linux-musl"
    else
        error "Unsupported architecture: $arch"
    fi

    mycelium_url="https://github.com/threefoldtech/mycelium/releases/latest/download/mycelium-${mycelium_arch}.tar.gz"
    
    if ! curl -L -o /tmp/mycelium.tar.gz "$mycelium_url"; then
        error "Failed to download Mycelium. Check your internet connection."
    fi

    log "Extracting Mycelium..."
    if ! tar -xf /tmp/mycelium.tar.gz -C /tmp; then
        error "Failed to extract Mycelium."
    fi

    log "Installing Mycelium..."
    if ! sudo mv /tmp/mycelium /usr/local/bin/mycelium && sudo chmod +x /usr/local/bin/mycelium; then
        error "Failed to install Mycelium. Ensure you have sudo privileges."
    fi

    # Clean up
    rm -f /tmp/mycelium.tar.gz

    log "Checking Mycelium version..."
    mycelium_version=$(/usr/local/bin/mycelium --version)
    log "Mycelium $mycelium_version installed successfully."

    # Enable IPv6 if disabled
    if [[ $(sysctl -n net.ipv6.conf.all.disable_ipv6) -eq 1 ]]; then
        log "Enabling IPv6..."
        if ! sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0; then
            warn "Failed to enable IPv6. Mycelium might not work properly."
        fi
    fi
}

# Set up OpenSSH server and disable password authentication
setup_open_ssh() {
    # Check if SSH server is installed
    if ! command -v sshd &> /dev/null; then
        log "OpenSSH server is not installed. Installing it now..."
        if ! sudo apt install openssh-server -y; then
            error "Failed to install OpenSSH server. Ensure you have sudo privileges."
        fi
    fi

    # Enable and start the SSH service
    log "Enabling and starting SSH service..."
    if ! sudo systemctl enable --now ssh; then
        error "Failed to enable/start SSH service. Ensure you have sudo privileges."
    fi

    # Check if the SSH configuration file exists
    if [[ ! -f /etc/ssh/sshd_config ]]; then
        error "SSH configuration file (/etc/ssh/sshd_config) not found. Ensure the SSH server is installed."
    fi

    log "Disabling password authentication in SSH..."
    log "Backing up SSH configuration..."
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    log "Updating SSH configuration with sudo..."
    if ! sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config; then
        error "Failed to update SSH configuration. Ensure you have sudo privileges."
    fi

    log "Verifying SSH configuration syntax..."
    if ! sudo sshd -t -f /etc/ssh/sshd_config; then
        error "SSH configuration syntax error. Restoring backup..."
        sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        error "SSH configuration restored from backup. Please check the file manually."
    fi

    # Reload systemd daemon to apply changes
    log "Reloading systemd daemon..."
    if ! sudo systemctl daemon-reload; then
        error "Failed to reload systemd daemon. Ensure you have sudo privileges."
    fi

    log "Restarting SSH service..."
    if ! sudo systemctl restart ssh; then
        error "Failed to restart SSH service. Ensure you have sudo privileges."
    fi

    log "Password authentication has been disabled. Only public key authentication is allowed."
}

# Create and configure Mycelium service
create_mycelium_service() {
    local node_type="$1"
    local peers=("tcp://188.40.132.242:9651" "quic://185.69.166.8:9651" "quic://185.206.122.71:9651" 
                "tcp://[2a04:f340:c0:71:28cc:b2ff:fe63:dd1c]:9651" "tcp://[2001:728:1000:402:78d3:cdff:fe63:e07e]:9651" 
                "quic://[2a10:b600:1:0:ec4:7aff:fe30:8235]:9651")
    
    local peers_string=$(printf " %s" "${peers[@]}")
    peers_string=${peers_string:1}  # Remove the leading space
    
    log "Creating Mycelium service for ${node_type} node..."
    
    # Create the service file
    cat << EOF | sudo tee /etc/systemd/system/mycelium.service > /dev/null
[Unit]
Description=End-2-end encrypted IPv6 overlay network
Wants=network.target
After=network.target
Documentation=https://github.com/threefoldtech/mycelium

[Service]
ProtectHome=true
ProtectSystem=true
SyslogIdentifier=mycelium
CapabilityBoundingSet=CAP_NET_ADMIN
StateDirectory=mycelium
StateDirectoryMode=0700
ExecStartPre=+-/sbin/modprobe tun
ExecStart=/usr/local/bin/mycelium --tun-name mycelium -k %S/mycelium/key.bin --peers ${peers_string}
Restart=always
RestartSec=5
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start the service
    log "Enabling and starting Mycelium service..."
    if ! sudo systemctl daemon-reload; then
        error "Failed to reload systemd daemon. Ensure you have sudo privileges."
    fi
    
    if ! sudo systemctl enable mycelium; then
        error "Failed to enable Mycelium service. Ensure you have sudo privileges."
    fi
    
    if ! sudo systemctl start mycelium; then
        error "Failed to start Mycelium service. Ensure you have sudo privileges."
    fi
    
    # Wait for Mycelium to start and get its address
    log "Waiting for Mycelium to start and obtain an address..."
    sleep 5
    
    local attempts=0
    local max_attempts=12
    local mycelium_info=""
    
    while [[ $attempts -lt $max_attempts ]]; do
        mycelium_info=$(mycelium inspect --json 2>/dev/null)
        if [[ -n "$mycelium_info" && "$mycelium_info" == *"address"* ]]; then
            break
        fi
        log "Waiting for Mycelium to initialize (attempt $((attempts+1))/$max_attempts)..."
        sleep 5
        attempts=$((attempts+1))
    done
    
    if [[ $attempts -eq $max_attempts ]]; then
        warn "Timed out waiting for Mycelium to initialize. You may need to check its status manually."
        return 1
    fi
    
    # Extract and display the Mycelium address
    local mycelium_address=$(echo "$mycelium_info" | grep -o '"address": "[^"]*' | sed 's/"address": "//')
    local public_key=$(echo "$mycelium_info" | grep -o '"publicKey": "[^"]*' | sed 's/"publicKey": "//')
    
    log "Mycelium service is running successfully."
    log "Mycelium Address: ${mycelium_address}"
    log "Public Key: ${public_key}"
    
    echo "$mycelium_address" > /tmp/mycelium_address
    echo "$public_key" > /tmp/mycelium_pubkey
    
    return 0
}

# Set up node with optional SSH or public key
setup_node() {
    local node_type="$1"
    local git_user="$2"

    log "Setting up a ${node_type} node..."
    
    # If a GitHub user is provided, set up public key authentication
    if [[ -n "$git_user" ]]; then
        local ssh_dir="$HOME/.ssh"
        local authorized_keys_file="$ssh_dir/authorized_keys"

        log "Setting up managed node with public key from GitHub user $git_user..."

        # Create .ssh directory if it doesn't exist
        if [[ ! -d "$ssh_dir" ]]; then
            log "Creating .ssh directory..."
            mkdir -p "$ssh_dir"
            chmod 700 "$ssh_dir"
        fi

        # Set up OpenSSH server and disable password authentication
        setup_open_ssh

        # Fetch public keys from GitHub
        log "Fetching public keys from GitHub..."
        if ! curl -s "https://github.com/$git_user.keys" -o /tmp/github_keys; then
            error "Failed to fetch public keys from GitHub. Check the GitHub username and your internet connection."
        fi

        # Append keys to authorized_keys file
        log "Appending public keys to authorized_keys..."
        cat /tmp/github_keys >> "$authorized_keys_file"
        chmod 600 "$authorized_keys_file"

        log "Public keys from GitHub user $git_user have been added to $authorized_keys_file."
    fi

    # Install Mycelium
    install_mycelium
    
    # Create and start Mycelium service
    create_mycelium_service "$node_type"
    
    if [[ -f /tmp/mycelium_address ]]; then
        local address=$(cat /tmp/mycelium_address)
        local pubkey=$(cat /tmp/mycelium_pubkey)
        
        log "${node_type^} node setup complete."
        log "You can connect to this node using the following Mycelium address: ${address}"
        log "Public Key: ${pubkey}"
        
        if [[ "$node_type" == "control" ]]; then
            log "This is a control node. You can SSH into your managed nodes using:"
            log "  ssh username@<managed-node-mycelium-address>"
        else
            log "This is a managed node. Your control node can SSH into this machine using:"
            log "  ssh $(whoami)@${address}"
        fi
    else
        warn "Failed to get Mycelium address. Check if Mycelium is running properly."
    fi
}

# Configure passwordless sudo for the current user
configure_passwordless_sudo() {
    local user=$(whoami)

    log "Configuring passwordless sudo for user $user..."

    # Add the user to the sudoers file with NOPASSWD
    if ! echo "$user ALL=(ALL) NOPASSWD: ALL" | sudo tee "/etc/sudoers.d/$user-nopasswd" > /dev/null; then
        error "Failed to configure passwordless sudo. Ensure you have sudo privileges."
    fi

    # Set the correct permissions for the sudoers file
    if ! sudo chmod 440 "/etc/sudoers.d/$user-nopasswd"; then
        error "Failed to set permissions for the sudoers file. Ensure you have sudo privileges."
    fi

    log "Passwordless sudo has been configured for user $user."
}

# Main execution
case "$1" in
    install)
        install
        ;;
    uninstall)
        uninstall
        ;;
    *)
        # Interactive menu
        echo
        echo -e "${GREEN}Welcome to the $DISPLAY_NAME tool!${NC}"
        echo
        echo "This tool sets up Mycelium networking between nodes."
        echo "Run this script on each managed node, then run it on the control node."
        echo

        while true; do
            echo "What would you like to do?"
            echo "1. Set a control node"
            echo "2. Set a managed node with SSH"
            echo "3. Set a managed node with public key"
            echo "4. Set a managed node with public key and passwordless sudo"
            echo "5. Exit"
            read -p "Please enter your choice [1-5]: " choice

            case $choice in
                1)
                    install_mycelium
                    setup_node "control"
                    log "Setup for control node for $DISPLAY_NAME is complete. Exiting..."
                    break
                    ;;
                2)
                    install_mycelium
                    setup_node "managed"
                    log "Setup for managed node for $DISPLAY_NAME is complete. Exiting..."
                    break
                    ;;
                3)
                    read -p "Enter the GitHub username: " git_user
                    install_mycelium
                    setup_node "managed" "$git_user"
                    log "Setup for managed node with public key for $DISPLAY_NAME is complete. Exiting..."
                    break
                    ;;
                4)
                    read -p "Enter the GitHub username: " git_user
                    install_mycelium
                    setup_node "managed" "$git_user"
                    configure_passwordless_sudo
                    log "Setup for managed node with public key and passwordless sudo for $DISPLAY_NAME is complete. Exiting..."
                    break
                    ;;
                5)
                    log "Exiting..."
                    break
                    ;;
                *)
                    warn "Invalid choice. Please enter a number between 1 and 5."
                    ;;
            esac
        done
        ;;
esac