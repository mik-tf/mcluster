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

# Function to remove a specific node from GitHub registry
remove_node_from_github() {
    local node_name="$1"
    
    if [[ -z "$node_name" ]]; then
        error "Node name is required. Usage: $SCRIPT_NAME remove-node <node_name>"
    fi
    
    setup_github_config
    
    log "Removing node '$node_name' from registry..."
    
    # Fetch current node information
    local current_content=$(fetch_node_info_from_github)
    
    # Check if this node exists in the file
    if ! echo "$current_content" | grep -q "^$node_name "; then
        error "Node '$node_name' not found in registry."
    fi
    
    # Remove the specific node entry
    local new_content=$(echo "$current_content" | grep -v "^$node_name ")
    
    # Get the current file's SHA
    local sha=$(gh api "repos/$GITHUB_REPO_OWNER/$GITHUB_REPO_NAME/contents/node_info.txt" --jq '.sha')
    
    if [[ -z "$sha" ]]; then
        error "Failed to get SHA for node_info.txt. Ensure the file exists and you have access to it."
    fi
    
    # Update the file with the new content
    local encoded_content=$(echo "$new_content" | base64 -w 0)
    local payload=$(jq -n \
        --arg message "Remove node $node_name" \
        --arg content "$encoded_content" \
        --arg sha "$sha" \
        '{message: $message, content: $content, sha: $sha}')

    if ! gh api -X PUT "repos/$GITHUB_REPO_OWNER/$GITHUB_REPO_NAME/contents/node_info.txt" --input - <<< "$payload" > /dev/null; then
        error "Failed to update node registry on GitHub."
    fi

    log "Node '$node_name' has been removed from the registry."
}

# Function to reset the node information file on GitHub
delete_node_info_from_github() {
    setup_github_config
    
    log "Resetting node registry to initial state..."
    
    # Get the current file's SHA and content
    local response=$(gh api "repos/$GITHUB_REPO_OWNER/$GITHUB_REPO_NAME/contents/node_info.txt" 2>/dev/null)
    
    if [[ -z "$response" ]]; then
        error "Failed to access node_info.txt. Ensure the file exists and you have access to it."
    fi
    
    local sha=$(echo "$response" | jq -r '.sha')
    
    # Keep only the first line (header) and reset the file
    local new_content="# Mycelium Cluster Node Registry"
    local encoded_content=$(echo "$new_content" | base64 -w 0)
    
    # Update the file with just the header line
    local payload=$(jq -n \
        --arg message "Reset node registry to initial state" \
        --arg content "$encoded_content" \
        --arg sha "$sha" \
        '{message: $message, content: $content, sha: $sha}')

    if ! gh api -X PUT "repos/$GITHUB_REPO_OWNER/$GITHUB_REPO_NAME/contents/node_info.txt" --input - <<< "$payload" > /dev/null; then
        error "Failed to reset node registry on GitHub."
    fi
    
    log "Node registry has been reset to initial state. All node information has been removed."
}

# Function to set up SSH keys for control node
setup_control_ssh_keys() {
    local ssh_dir="$HOME/.ssh"
    
    log "Setting up SSH keys for cluster control..."
    
    # Create SSH directory if it doesn't exist
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    
    # Find all potential SSH key pairs in the .ssh directory
    local key_files=()
    local key_names=()
    
    # Check for common key types
    for key_type in id_ed25519 id_rsa id_ecdsa id_dsa; do
        if [[ -f "$ssh_dir/$key_type" && -f "$ssh_dir/$key_type.pub" ]]; then
            key_files+=("$ssh_dir/$key_type")
            key_names+=("$key_type")
        fi
    done
    
    # Present options to the user
    if [[ ${#key_files[@]} -gt 0 ]]; then
        echo "Found existing SSH keys:"
        for i in "${!key_names[@]}"; do
            echo "$((i+1)). ${key_names[$i]}"
        done
        echo "$((${#key_files[@]}+1)). Generate new SSH keys"
        echo "$((${#key_files[@]}+2)). Use keys from another location"
        echo "$((${#key_files[@]}+3)). Paste private and public key"
        
        read -p "Enter your choice [1-$((${#key_files[@]}+3))]: " key_choice
        
        # Validate input
        if [[ ! "$key_choice" =~ ^[0-9]+$ || "$key_choice" -lt 1 || "$key_choice" -gt $((${#key_files[@]}+3)) ]]; then
            error "Invalid choice. Please enter a number between 1 and $((${#key_files[@]}+3))."
        fi
        
        if [[ "$key_choice" -le ${#key_files[@]} ]]; then
            # User chose an existing key
            local selected_index=$((key_choice-1))
            key_file="${key_files[$selected_index]}"
            pub_key_file="${key_file}.pub"
            log "Using existing SSH key: $key_file"
        elif [[ "$key_choice" -eq $((${#key_files[@]}+1)) ]]; then
            # Generate new keys
            key_file="$ssh_dir/mcluster_id_ed25519"
            pub_key_file="${key_file}.pub"
            
            log "Generating new SSH key pair..."
            ssh-keygen -t ed25519 -N "" -f "$key_file" -C "mcluster_key"
            
            if [[ ! -f "$key_file" || ! -f "$pub_key_file" ]]; then
                error "Failed to generate SSH key pair."
            fi
            
            chmod 600 "$key_file"
            chmod 644 "$pub_key_file"
            log "New SSH key pair generated at $key_file"
        elif [[ "$key_choice" -eq $((${#key_files[@]}+2)) ]]; then
            # Import keys from another location
            read -p "Enter path to private key file: " import_key_file
            read -p "Enter path to public key file: " import_pub_key_file
            
            if [[ ! -f "$import_key_file" || ! -f "$import_pub_key_file" ]]; then
                error "One or both key files not found. Please check the paths."
            fi
            
            # Determine the key name from the file path
            local key_basename=$(basename "$import_key_file")
            key_file="$ssh_dir/mcluster_$key_basename"
            pub_key_file="${key_file}.pub"
            
            cp "$import_key_file" "$key_file"
            cp "$import_pub_key_file" "$pub_key_file"
            
            chmod 600 "$key_file"
            chmod 644 "$pub_key_file"
            log "SSH key pair imported to $key_file"
        else
            # Paste keys
            key_file="$ssh_dir/id_ed25519"
            pub_key_file="${key_file}.pub"
            
            echo "Paste your private key content (Ctrl+D when done):"
            private_key_content=$(cat)
            
            echo "Paste your public key content (Ctrl+D when done):"
            public_key_content=$(cat)
            
            # Write the key content to files
            echo "$private_key_content" > "$key_file"
            echo "$public_key_content" > "$pub_key_file"
            
            chmod 600 "$key_file"
            chmod 644 "$pub_key_file"
            log "SSH key pair saved at $key_file"
        fi
    else
        # No existing keys found
        echo "No SSH keys found in $ssh_dir"
        echo "1. Generate new SSH keys"
        echo "2. Import keys from another location"
        echo "3. Paste private and public key"
        
        read -p "Enter your choice [1-3]: " key_choice
        
        case $key_choice in
            1)
                # Generate new keys
                key_file="$ssh_dir/id_ed25519"
                pub_key_file="${key_file}.pub"
                
                log "Generating new SSH key pair..."
                ssh-keygen -t ed25519 -N "" -f "$key_file" -C "mcluster_key"
                
                if [[ ! -f "$key_file" || ! -f "$pub_key_file" ]]; then
                    error "Failed to generate SSH key pair."
                fi
                
                chmod 600 "$key_file"
                chmod 644 "$pub_key_file"
                log "SSH key pair generated at $key_file"
                ;;
            2)
                # Import keys from another location
                read -p "Enter path to private key file: " import_key_file
                read -p "Enter path to public key file: " import_pub_key_file
                
                if [[ ! -f "$import_key_file" || ! -f "$import_pub_key_file" ]]; then
                    error "One or both key files not found. Please check the paths."
                fi
                
                # Determine the key name from the file path
                local key_basename=$(basename "$import_key_file")
                key_file="$ssh_dir/$key_basename"
                pub_key_file="${key_file}.pub"
                
                cp "$import_key_file" "$key_file"
                cp "$import_pub_key_file" "$pub_key_file"
                
                chmod 600 "$key_file"
                chmod 644 "$pub_key_file"
                log "SSH key pair imported to $key_file"
                ;;
            3)
                # Paste keys
                key_file="$ssh_dir/id_ed25519"
                pub_key_file="${key_file}.pub"
                
                echo "Paste your private key content (Ctrl+D when done):"
                private_key_content=$(cat)
                
                echo "Paste your public key content (Ctrl+D when done):"
                public_key_content=$(cat)
                
                # Write the key content to files
                echo "$private_key_content" > "$key_file"
                echo "$public_key_content" > "$pub_key_file"
                
                chmod 600 "$key_file"
                chmod 644 "$pub_key_file"
                log "SSH key pair saved at $key_file"
                ;;
            *)
                error "Invalid choice. Please enter 1, 2, or 3."
                ;;
        esac
    fi
    
    # Add entry to SSH config to use this key for mycelium addresses
    local ssh_config="$ssh_dir/config"
    touch "$ssh_config"  # Create if doesn't exist
    
    if ! grep -q "# mcluster configuration" "$ssh_config" 2>/dev/null; then
        log "Adding mycelium configuration to SSH config..."
        cat >> "$ssh_config" << EOF

# mcluster configuration
Host fd00:*
    IdentityFile $key_file
    User $(whoami)
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    AddressFamily inet6
EOF
    else
        # Update the IdentityFile line if configuration already exists
        sed -i "s|IdentityFile .*|IdentityFile $key_file|" "$ssh_config"
    fi
    
    # Read the public key content for later use
    local pub_key_content=$(cat "$pub_key_file")
    
    log "SSH keys set up successfully."
    echo "$pub_key_content" > /tmp/ssh_pubkey
    return 0
}

# Function to set up authorized keys for managed nodes
setup_authorized_keys() {
    log "Setting up authorized keys for SSH access..."
    
    # Fetch node information from GitHub
    local node_info=$(fetch_node_info_from_github)
    
    # Get control nodes with SSH keys
    local control_nodes=$(echo "$node_info" | grep -v "^#" | grep "control" | grep -v "^$")
    
    if [[ -z "$control_nodes" ]]; then
        warn "No control nodes with SSH keys found in the cluster. SSH access may not work."
        return 1
    fi
    
    local ssh_dir="$HOME/.ssh"
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    
    local auth_keys="$ssh_dir/authorized_keys"
    touch "$auth_keys"
    chmod 600 "$auth_keys"
    
    # Process control nodes and add their SSH keys to authorized_keys
    while read -r line; do
        # Format is: node_name mycelium_address public_key node_type ssh_pubkey
        # We need the 5th field (ssh_pubkey)
        local name=$(echo "$line" | awk '{print $1}')
        local ssh_key=$(echo "$line" | awk '{$1=$2=$3=$4=""; print $0}' | sed 's/^[ \t]*//')
        
        # Check if this looks like an SSH key (starts with ssh-)
        if [[ "$ssh_key" == ssh-* ]]; then
            log "Adding SSH key from control node $name"
            
            # Only add the key if it's not already in the file
            if ! grep -q "$ssh_key" "$auth_keys"; then
                echo "# mcluster: $name" >> "$auth_keys"
                echo "$ssh_key" >> "$auth_keys"
            fi
        fi
    done <<< "$control_nodes"
    
    log "Authorized keys set up successfully."
}

# Function to update node information on GitHub
update_node_info_on_github() {
    local node_name="$1"
    local mycelium_address="$2"
    local public_key="$3"
    local node_type="$4"
    local ssh_pubkey="$5"  # Optional SSH public key

    setup_github_config
    
    log "Updating node information on GitHub..."
    local current_content=$(fetch_node_info_from_github)
    
    # Check if this node already exists in the file
    if echo "$current_content" | grep -q "^$node_name "; then
        log "Node $node_name already exists in registry. Updating information..."
        # Remove the existing entry
        current_content=$(echo "$current_content" | grep -v "^$node_name ")
    fi
    
    local new_entry="$node_name $mycelium_address $public_key $node_type"
    if [[ -n "$ssh_pubkey" ]]; then
        new_entry="$new_entry $ssh_pubkey"
    fi
    
    local new_content="$current_content"$'\n'"$new_entry"
    
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
    echo "$node_info" | while IFS=' ' read -r name address publickey type rest; do
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

check_existing_node() {
    # Check if the Mycelium service is already running
    if sudo systemctl is-active --quiet mcluster.service; then
        # Service exists and is active
        local node_type=""
        
        # Try to determine if it's a control or managed node
        if [[ -f /tmp/mycelium_address ]]; then
            local address=$(cat /tmp/mycelium_address)
            
            # Fetch node info from GitHub
            local node_info=$(fetch_node_info_from_github)
            
            # Look for this address in the node info
            local node_entry=$(echo "$node_info" | grep "$address")
            
            if [[ -n "$node_entry" ]]; then
                node_type=$(echo "$node_entry" | awk '{print $4}')
            fi
        fi
        
        # If we couldn't determine the node type, check for SSH keys setup
        if [[ -z "$node_type" ]]; then
            if grep -q "# mcluster configuration" "$HOME/.ssh/config" 2>/dev/null; then
                node_type="control"
            else
                node_type="managed"
            fi
        fi
        
        log "This machine appears to be already configured as a ${node_type} node."
        read -p "Do you want to reconfigure it? This may disrupt existing connections. [y/N]: " confirm
        
        if [[ "${confirm,,}" != "y" ]]; then
            log "Operation cancelled. Existing node configuration preserved."
            exit 0
        fi
        
        log "Proceeding with reconfiguration..."
        return 0
    fi
    
    # Check for SSH config which would indicate a control node
    if grep -q "# mcluster configuration" "$HOME/.ssh/config" 2>/dev/null && [[ ! -f "/tmp/is_reconfiguring" ]]; then
        log "This machine appears to have SSH configuration for a control node."
        read -p "Do you want to reconfigure it? [y/N]: " confirm
        
        if [[ "${confirm,,}" != "y" ]]; then
            log "Operation cancelled."
            exit 0
        fi
        
        # Create a temporary marker to avoid repeated prompts
        touch "/tmp/is_reconfiguring"
        log "Proceeding with reconfiguration..."
    fi
    
    return 0
}

# Create and configure Mycelium service
create_mycelium_service() {
    local node_type="$1"
    
    log "Creating Mycelium service for ${node_type} node..."
    
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
    local mycelium_address=""
    local public_key="unknown"
    
    while [[ $attempts -lt $max_attempts ]]; do
        # Attempt to get the global IPv6 address using ip command
        mycelium_address=$(ip -6 addr show utun9 2>/dev/null | grep -v 'fe80::' | grep 'scope global' | grep -oP '([a-f0-9:]+)(?=\/)')
        
        # If that fails, try with ifconfig
        if [[ -z "$mycelium_address" ]]; then
            mycelium_address=$(ifconfig utun9 2>/dev/null | grep 'inet6' | grep -v 'fe80' | awk '{print $2}')
        fi
        
        # If we found an address, break the loop
        if [[ -n "$mycelium_address" ]]; then
            log "Found Mycelium address: $mycelium_address"
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
    
    # Try to get the public key using mycelium inspect if possible
    # First find the key file location
    local key_locations=(
        "/var/lib/mycelium/priv_key.bin"
        "/etc/mycelium/priv_key.bin"
        "$HOME/.mycelium/priv_key.bin"
        "/run/mycelium/priv_key.bin"
    )
    
    for key_file in "${key_locations[@]}"; do
        if sudo test -f "$key_file" 2>/dev/null; then
            log "Found key file at $key_file, attempting to extract public key..."
            pk_output=$(sudo mycelium inspect --json "$key_file" 2>/dev/null)
            if [[ -n "$pk_output" && "$pk_output" == *"publicKey"* ]]; then
                public_key=$(echo "$pk_output" | grep -o '"publicKey": "[^"]*' | sed 's/"publicKey": "//')
                break
            fi
        fi
    done
    
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

    # For control nodes, set up SSH keys
    local ssh_pubkey=""
    if [[ "$node_type" == "control" ]]; then
        setup_control_ssh_keys
        if [[ -f /tmp/ssh_pubkey ]]; then
            ssh_pubkey=$(cat /tmp/ssh_pubkey)
        fi
    fi

    check_existing_node

    # Install Mycelium
    install_mycelium

    # Create and start Mycelium service
    create_mycelium_service "$node_type"

    # For managed nodes, set up SSH server and authorized keys
    if [[ "$node_type" == "managed" ]]; then
        setup_open_ssh
        setup_authorized_keys
    fi

    if [[ -f /tmp/mycelium_address ]]; then
        local address=$(cat /tmp/mycelium_address)
        local pubkey=$(cat /tmp/mycelium_pubkey)

        # Share this node's information with the cluster via GitHub
        if [[ -n "$ssh_pubkey" ]]; then
            update_node_info_on_github "$node_name" "$address" "$pubkey" "$node_type" "$ssh_pubkey"
        else
            update_node_info_on_github "$node_name" "$address" "$pubkey" "$node_type"
        fi

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
    delete-list)
        read -p "Are you sure you want to delete the node registry? This will remove all node information. Type 'yes' to confirm: " confirm
        if [[ "$confirm" == "yes" ]]; then
            delete_node_info_from_github
        else
            log "Operation cancelled."
        fi
        ;;
    remove-node)
        remove_node_from_github "$2"
        ;;
    *)
        # Interactive menu
        echo
        echo -e "${GREEN}Welcome to the $DISPLAY_NAME tool!${NC}"
        echo
        echo "This tool sets up Mycelium networking between nodes."
        echo "Run this script on each managed node, then run it on the control node."
        echo
        
        # Main menu loop
        while true; do
            echo "What would you like to do?"
            echo "1. Set a control node (used to manage other nodes)"
            echo "2. Set a managed node (will be accessed by control node)"
            echo "3. Set a managed node with passwordless sudo"
            echo "4. List all nodes in the cluster"
            echo "5. Delete node registry"
            echo "6. Remove a specific node"
            echo "7. Exit"
            read -p "Please enter your choice [1-7]: " choice

            case $choice in
                1)
                    read -p "Enter a name for this control node: " node_name
                    setup_node "control" "" "$node_name"
                    log "Setup for control node for $DISPLAY_NAME is complete. Exiting..."
                    exit 0
                    ;;
                2)
                    read -p "Enter a name for this managed node: " node_name
                    setup_node "managed" "" "$node_name"
                    log "Setup for managed node for $DISPLAY_NAME is complete. Exiting..."
                    exit 0
                    ;;
                3)
                    read -p "Enter a name for this managed node: " node_name
                    setup_node "managed" "" "$node_name"
                    configure_passwordless_sudo
                    log "Setup for managed node with passwordless sudo for $DISPLAY_NAME is complete. Exiting..."
                    exit 0
                    ;;
                4)
                    list_nodes
                    ;;
                5)
                        read -p "Are you sure you want to delete the node registry? This will remove all node information. Type 'yes' to confirm: " confirm
                        if [[ "$confirm" == "yes" ]]; then
                            delete_node_info_from_github
                        else
                            log "Operation cancelled."
                        fi
                        ;;
                6)
                    read -p "Enter the name of the node to remove: " node_name
                    if [[ -n "$node_name" ]]; then
                        remove_node_from_github "$node_name"
                    else
                        warn "Node name cannot be empty."
                    fi
                    ;;
                7)
                    log "Exiting..."
                    exit 0
                    ;;
                *)
                    warn "Invalid choice. Please enter a number between 1 and 7."
                    ;;
            esac
        done
        ;;
esac
