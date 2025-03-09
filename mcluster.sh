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

# Install GitHub CLI if not already installed
install_gh_cli() {
    if ! command -v gh &> /dev/null; then
        log "Installing GitHub CLI..."
        if ! sudo apt update || ! sudo apt install -y gh; then
            error "Failed to install GitHub CLI. Please install it manually: https://cli.github.com/"
        fi
    fi
}

# Authenticate with GitHub via browser
authenticate_with_github() {
    log "Authenticating with GitHub..."
    if ! gh auth login --hostname github.com --web; then
        error "Failed to authenticate with GitHub. Please try again."
    fi
    log "GitHub authentication successful."
}

# GitHub API configuration - these will be set by setup_github_config
GITHUB_REPO_OWNER=""
GITHUB_REPO_NAME=""
GITHUB_API_URL=""

# Function to set up GitHub repository configuration
setup_github_config() {
    # Config file location
    local config_dir="$HOME/.config/mcluster"
    local config_file="$config_dir/config"
    
    # Check if configuration already exists
    if [[ -f "$config_file" ]]; then
        # Load existing configuration
        source "$config_file"
        log "Loaded existing GitHub configuration."
        return 0
    fi
    
    # Ensure GitHub CLI is installed
    install_gh_cli
    
    # Ensure the user is authenticated with GitHub
    if ! gh auth status &>/dev/null; then
        authenticate_with_github
    fi
    
    # Ask for GitHub username if not already provided
    if [[ -z "$GITHUB_REPO_OWNER" ]]; then
        # Try to get the username from GitHub CLI
        local default_username=$(gh api user --jq '.login' 2>/dev/null)
        read -p "Enter your GitHub username [$default_username]: " input_username
        GITHUB_REPO_OWNER=${input_username:-$default_username}
        
        if [[ -z "$GITHUB_REPO_OWNER" ]]; then
            error "GitHub username is required."
        fi
    fi
    
    # Set repository name based on username
    GITHUB_REPO_NAME="mcluster_${GITHUB_REPO_OWNER}"
    GITHUB_API_URL="https://api.github.com/repos/$GITHUB_REPO_OWNER/$GITHUB_REPO_NAME/contents/node_info.txt"
    
    # Check if the repository exists
    if ! gh repo view "$GITHUB_REPO_OWNER/$GITHUB_REPO_NAME" &>/dev/null; then
        log "Repository $GITHUB_REPO_NAME does not exist. Creating it..."
        
        # Create a private repository
        if ! gh repo create "$GITHUB_REPO_NAME" --private --description "Mycelium Cluster Node Registry" --confirm; then
            error "Failed to create repository. Please check your GitHub access."
        fi
        
        # Initialize node_info.txt with a header
        echo "# Mycelium Cluster Node Registry" | gh api -X PUT "repos/$GITHUB_REPO_OWNER/$GITHUB_REPO_NAME/contents/node_info.txt" \
            -f message="Initialize node registry" \
            -f content="$(echo "# Mycelium Cluster Node Registry" | base64)"
        
        log "Created private repository: $GITHUB_REPO_OWNER/$GITHUB_REPO_NAME"
    else
        log "Using existing repository: $GITHUB_REPO_OWNER/$GITHUB_REPO_NAME"
    fi
    
    # Save configuration
    mkdir -p "$config_dir"
    cat > "$config_file" << EOF
GITHUB_REPO_OWNER="$GITHUB_REPO_OWNER"
GITHUB_REPO_NAME="$GITHUB_REPO_NAME"
GITHUB_API_URL="$GITHUB_API_URL"
EOF
    
    log "GitHub configuration saved."
}

# Function to fetch node information from GitHub
fetch_node_info_from_github() {
    setup_github_config
    
    log "Fetching node information from GitHub..."
    local response=$(gh api "repos/$GITHUB_REPO_OWNER/$GITHUB_REPO_NAME/contents/node_info.txt" 2>/dev/null)
    
    if [[ -z "$response" ]]; then
        warn "Failed to fetch node information from GitHub."
        return 1
    fi
    
    local content=$(echo "$response" | jq -r '.content' | base64 --decode)
    echo "$content"
}

# Function to update node information on GitHub
update_node_info_on_github() {
    local node_name="$1"
    local mycelium_address="$2"
    local public_key="$3"
    local node_type="$4"  # Add node type parameter

    setup_github_config
    
    log "Updating node information on GitHub..."
    local current_content=$(fetch_node_info_from_github)
    
    # Check if this node already exists in the file
    if echo "$current_content" | grep -q "^$node_name "; then
        log "Node $node_name already exists in registry. Updating information..."
        # Remove the existing entry
        current_content=$(echo "$current_content" | grep -v "^$node_name ")
    fi
    
    local new_content="$current_content"$'\n'"$node_name $mycelium_address $public_key $node_type"
    
    # Remove any blank lines
    new_content=$(echo "$new_content" | grep -v "^$")

    # Get the current file's SHA
    local sha=$(gh api "repos/$GITHUB_REPO_OWNER/$GITHUB_REPO_NAME/contents/node_info.txt" --jq '.sha')
    
    if [[ -z "$sha" ]]; then
        error "Failed to get SHA for node_info.txt. Ensure the file exists and you have access to it."
    fi
    
    # Update the file with the new content
    local encoded_content=$(echo "$new_content" | base64 -w 0)
    local payload=$(jq -n \
        --arg message "Update node $node_name" \
        --arg content "$encoded_content" \
        --arg sha "$sha" \
        '{message: $message, content: $content, sha: $sha}')

    if ! gh api -X PUT "repos/$GITHUB_REPO_OWNER/$GITHUB_REPO_NAME/contents/node_info.txt" --input - <<< "$payload" > /dev/null; then
        error "Failed to update node information on GitHub."
    fi

    log "Node information updated on GitHub."
}

# Function to list all nodes in the cluster
list_nodes() {
    log "Fetching cluster node information..."
    
    # Try to fetch the node info from GitHub
    if ! command -v gh &> /dev/null; then
        install_gh_cli
    fi
    
    # Set up GitHub configuration
    setup_github_config
    
    # Fetch node information
    local node_info=$(fetch_node_info_from_github)
    
    if [[ -z "$node_info" ]]; then
        warn "No node information found or unable to fetch data."
        return 1
    fi
    
    # Display header
    echo
    echo -e "${BLUE}========== MYCELIUM CLUSTER NODES ==========${NC}"
    echo -e "${BLUE}Node Name          Mycelium Address                              Type${NC}"
    echo -e "${BLUE}------------------------------------------------------------------${NC}"
    
    # Process and display each line of node information
    echo "$node_info" | while IFS=' ' read -r name address publickey type; do
        # Skip lines that start with # (comments) or empty lines
        if [[ -z "$name" || "$name" == \#* ]]; then
            continue
        fi
        
        # If type isn't specified, try to determine it
        if [[ -z "$type" ]]; then
            # Default to "managed" if unknown
            type="managed"
        fi
        
        # Format the output
        printf "%-18s %-42s %-10s\n" "$name" "$address" "$type"
    done
    
    echo
    log "To connect to a managed node, use: ssh username@<Mycelium-Address>"
}

# Function to install Mycelium
install_mycelium() {
    log "Updating package list..."
    if ! sudo apt update; then
        error "Failed to update package list. Ensure you have sudo privileges."
    fi

    log "Installing dependencies..."
    if ! sudo apt install -y curl tar jq; then
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
    
    log "Creating Mycelium service for ${node_type} node..."
    
    # Create the service file using exactly your desired configuration
    cat << EOF | sudo tee /etc/systemd/system/mcluster.service > /dev/null
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
ExecStart=/usr/local/bin/mycelium --peers tcp://188.40.132.242:9651 quic://185.69.166.8:9651 --tun-name utun9
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
    
    if ! sudo systemctl enable mcluster; then
        error "Failed to enable Mycelium service. Ensure you have sudo privileges."
    fi
    
    if ! sudo systemctl start mcluster; then
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
    local node_name="$3"

    log "Setting up a ${node_type} node..."

    # Install GitHub CLI if not already installed
    install_gh_cli

    # Authenticate with GitHub and set up repository
    setup_github_config

    # Install Mycelium
    install_mycelium

    # Create and start Mycelium service
    create_mycelium_service "$node_type"

    if [[ -f /tmp/mycelium_address ]]; then
        local address=$(cat /tmp/mycelium_address)
        local pubkey=$(cat /tmp/mycelium_pubkey)

        # Share this node's information with the cluster via GitHub
        update_node_info_on_github "$node_name" "$address" "$pubkey" "$node_type"

        # Fetch and display information about other nodes in the cluster
        log "Fetching information about other nodes in the cluster..."
        list_nodes

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
    list)
        list_nodes
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
            echo "5. List all nodes in the cluster"
            echo "6. Exit"
            read -p "Please enter your choice [1-6]: " choice

            case $choice in
                1)
                    read -p "Enter a name for this control node: " node_name
                    setup_node "control" "" "$node_name"
                    log "Setup for control node for $DISPLAY_NAME is complete. Exiting..."
                    break
                    ;;
                2)
                    read -p "Enter a name for this managed node: " node_name
                    setup_node "managed" "" "$node_name"
                    log "Setup for managed node for $DISPLAY_NAME is complete. Exiting..."
                    break
                    ;;
                3)
                    read -p "Enter a name for this managed node: " node_name
                    setup_node "managed" "" "$node_name"
                    log "Setup for managed node with public key for $DISPLAY_NAME is complete. Exiting..."
                    break
                    ;;
                4)
                    read -p "Enter a name for this managed node: " node_name
                    setup_node "managed" "" "$node_name"
                    configure_passwordless_sudo
                    log "Setup for managed node with public key and passwordless sudo for $DISPLAY_NAME is complete. Exiting..."
                    break
                    ;;
                5)
                    list_nodes
                    ;;
                6)
                    log "Exiting..."
                    break
                    ;;
                *)
                    warn "Invalid choice. Please enter a number between 1 and 6."
                    ;;
            esac
        done
        ;;
esac