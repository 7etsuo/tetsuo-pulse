#!/bin/bash
#
# tmux-todo-runner.sh
#
# Dynamically generates and executes grok commands in tmux windows with 5 splits each.
# Combines subdirectory filters (-core, -http, etc.) with command templates (-security, etc.).
# Waits for user confirmation before proceeding to the next command.
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get the repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Available subdirectory filters
SUBDIRS=("core" "dns" "http" "poll" "pool" "socket" "tls")

# Available command templates
CMD_TEMPLATES=("redundancy" "refactor" "security" "comment")

# Selected filters and templates
declare -a SELECTED_SUBDIRS=()
declare -a SELECTED_TEMPLATES=()
HEADERS_ONLY=false

# Show usage/help
show_help() {
    echo -e "${GREEN}tmux-todo-runner.sh${NC} - Generate and run grok commands in tmux windows"
    echo ""
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 <SUBDIRS...> <TEMPLATES...>"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  -h, --help     Show this help message"
    echo "  -l, --list     List available subdirectories with file counts"
    echo "  -headers       Process header files only (use with -comment)"
    echo ""
    echo -e "${YELLOW}Subdirectory Filters:${NC} (select which src/ subdirs to process)"
    echo "  -core          Process src/core/*.c files (or include/core/*.h with -headers)"
    echo "  -dns           Process src/dns/*.c files (or include/dns/*.h with -headers)"
    echo "  -http          Process src/http/*.c files (or include/http/*.h with -headers)"
    echo "  -poll          Process src/poll/*.c files (or include/poll/*.h with -headers)"
    echo "  -pool          Process src/pool/*.c files (or include/pool/*.h with -headers)"
    echo "  -socket        Process src/socket/*.c files (or include/socket/*.h with -headers)"
    echo "  -tls           Process src/tls/*.c files (or include/tls/*.h with -headers)"
    echo ""
    echo -e "${YELLOW}Command Templates:${NC} (select which .cursor/commands/*.md to use)"
    echo "  -redundancy    Use @.cursor/commands/redundancy.md (.c files only)"
    echo "  -refactor      Use @.cursor/commands/refactor.md (.c files only)"
    echo "  -security      Use @.cursor/commands/security.md (.c files only)"
    echo "  -comment       Use @.cursor/commands/comment.md (.c and .h files, or .h only with -headers)"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 -core -security              # security.md on core .c files"
    echo "  $0 -http -redundancy            # redundancy.md on http .c files"
    echo "  $0 -core -redundancy -refactor  # both templates on core .c files"
    echo "  $0 -socket -tls -security       # security.md on socket+tls .c files"
    echo "  $0 -core -comment               # comment.md on core .c and .h files"
    echo "  $0 -core -comment -headers      # comment.md on core .h files only"
    echo "  $0 -comment -headers            # comment.md on ALL .h files (all subdirs)"
    echo ""
}

# List subdirectories with file counts
list_subdirs() {
    echo -e "${GREEN}Available subdirectories:${NC}"
    echo ""
    printf "  ${CYAN}%-10s${NC} %-25s %-10s %-25s %s\n" "Flag" "Source Path" "Files" "Header Path" "Files"
    printf "  %-10s %-25s %-10s %-25s %s\n" "----" "-----------" "-----" "-----------" "-----"

    local total_c=0
    local total_h=0
    for subdir in "${SUBDIRS[@]}"; do
        local src_path="${REPO_ROOT}/src/${subdir}"
        local include_path="${REPO_ROOT}/include/${subdir}"

        local count_c=0
        local count_h=0

        # Count .c files
        if [ -d "$src_path" ]; then
            count_c=$(find "$src_path" -maxdepth 1 -name "*.c" -type f | wc -l)
        fi

        # Count .h files
        if [ -d "$include_path" ]; then
            count_h=$(find "$include_path" -maxdepth 1 -name "*.h" -type f | wc -l)
        fi

        printf "  ${YELLOW}-%-9s${NC} src/%-19s %-10s" "$subdir" "${subdir}/*.c" "$count_c"
        if [ "$count_h" -gt 0 ]; then
            printf " include/%-19s %s\n" "${subdir}/*.h" "$count_h"
        else
            printf " %-25s -\n" "(no headers)"
        fi

        ((total_c += count_c)) || true
        ((total_h += count_h)) || true
    done

    echo ""
    printf "  ${GREEN}%-10s${NC} %-25s %-10s" "(total)" "src/*/*.c" "$total_c"
    if [ "$total_h" -gt 0 ]; then
        printf " include/*/*.h          %s\n" "$total_h"
    else
        printf " %-25s -\n" "(no headers)"
    fi
    echo ""

    echo -e "${GREEN}Available command templates:${NC}"
    echo ""
    for tmpl in "${CMD_TEMPLATES[@]}"; do
        if [ "$tmpl" = "comment" ]; then
            echo -e "  ${YELLOW}-${tmpl}${NC}    @.cursor/commands/${tmpl}.md (supports .c/.h files, use -headers for .h only)"
        else
            echo -e "  ${YELLOW}-${tmpl}${NC}    @.cursor/commands/${tmpl}.md (.c files only)"
        fi
    done
    echo ""
}

# Build the prompt string from selected templates
build_prompt() {
    local prompt="@.cursorrules"
    
    for tmpl in "${SELECTED_TEMPLATES[@]}"; do
        prompt="${prompt} @.cursor/commands/${tmpl}.md"
    done
    
    echo "$prompt"
}

# Generate command for a file
generate_command() {
    local filepath="$1"
    local prompt="$2"
    
    # Convert absolute path to @src/... format
    local rel_path="${filepath#${REPO_ROOT}/}"
    
    echo "grok --yolo --prompt \"${prompt} @${rel_path}\""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -l|--list)
            list_subdirs
            exit 0
            ;;
        -core)
            SELECTED_SUBDIRS+=("core")
            shift
            ;;
        -dns)
            SELECTED_SUBDIRS+=("dns")
            shift
            ;;
        -http)
            SELECTED_SUBDIRS+=("http")
            shift
            ;;
        -poll)
            SELECTED_SUBDIRS+=("poll")
            shift
            ;;
        -pool)
            SELECTED_SUBDIRS+=("pool")
            shift
            ;;
        -socket)
            SELECTED_SUBDIRS+=("socket")
            shift
            ;;
        -tls)
            SELECTED_SUBDIRS+=("tls")
            shift
            ;;
        -redundancy)
            SELECTED_TEMPLATES+=("redundancy")
            shift
            ;;
        -refactor)
            SELECTED_TEMPLATES+=("refactor")
            shift
            ;;
        -security)
            SELECTED_TEMPLATES+=("security")
            shift
            ;;
        -comment)
            SELECTED_TEMPLATES+=("comment")
            shift
            ;;
        -headers)
            HEADERS_ONLY=true
            shift
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $1${NC}" >&2
            echo "Use -h or --help for usage information" >&2
            exit 1
            ;;
    esac
done

# Special case: if -comment -headers is used without subdirs, select all subdirs
if [ ${#SELECTED_SUBDIRS[@]} -eq 0 ] && [ "$HEADERS_ONLY" = true ]; then
    has_comment=false
    for tmpl in "${SELECTED_TEMPLATES[@]}"; do
        if [ "$tmpl" = "comment" ]; then
            has_comment=true
            break
        fi
    done
    if [ "$has_comment" = true ]; then
        # Auto-select all subdirectories
        SELECTED_SUBDIRS=("${SUBDIRS[@]}")
        echo -e "${CYAN}Auto-selected all subdirectories for -comment -headers${NC}"
    fi
fi

# Validate: need at least one subdir and one template
if [ ${#SELECTED_SUBDIRS[@]} -eq 0 ]; then
    echo -e "${RED}Error: No subdirectory selected${NC}" >&2
    echo "Use at least one of: -core, -dns, -http, -poll, -pool, -socket, -tls" >&2
    echo "Or use -comment -headers to process all header files" >&2
    echo "Use -h or --help for usage information" >&2
    exit 1
fi

if [ ${#SELECTED_TEMPLATES[@]} -eq 0 ]; then
    echo -e "${RED}Error: No command template selected${NC}" >&2
    echo "Use at least one of: -redundancy, -refactor, -security, -comment" >&2
    echo "Use -h or --help for usage information" >&2
    exit 1
fi

# Validate -headers flag usage
if [ "$HEADERS_ONLY" = true ]; then
    has_comment=false
    for tmpl in "${SELECTED_TEMPLATES[@]}"; do
        if [ "$tmpl" = "comment" ]; then
            has_comment=true
            break
        fi
    done
    if [ "$has_comment" = false ]; then
        echo -e "${RED}Error: -headers flag can only be used with -comment${NC}" >&2
        echo "Use -h or --help for usage information" >&2
        exit 1
    fi
fi

# Check if tmux is available
if ! command -v tmux &> /dev/null; then
    echo -e "${RED}Error: tmux is not installed${NC}" >&2
    exit 1
fi

# Check if we're inside a tmux session
if [ -z "${TMUX:-}" ]; then
    echo -e "${RED}Error: Not running inside a tmux session${NC}" >&2
    echo "Please start tmux first or attach to an existing session" >&2
    exit 1
fi

# Build the prompt string
PROMPT_STRING=$(build_prompt)

# Show configuration
echo -e "${CYAN}Subdirectories:${NC} ${SELECTED_SUBDIRS[*]}"
echo -e "${CYAN}Templates:${NC} ${SELECTED_TEMPLATES[*]}"
echo -e "${CYAN}Prompt:${NC} ${PROMPT_STRING}"
echo ""

# Collect files from selected subdirectories
# For comment template: include both .c and .h files, or only .h files if -headers is set
# For other templates: include only .c files
declare -a ALL_FILES=()

# Check if comment template is selected
COMMENT_SELECTED=false
for tmpl in "${SELECTED_TEMPLATES[@]}"; do
    if [ "$tmpl" = "comment" ]; then
        COMMENT_SELECTED=true
        break
    fi
done

for subdir in "${SELECTED_SUBDIRS[@]}"; do
    if [ "$COMMENT_SELECTED" = true ] && [ "$HEADERS_ONLY" = true ]; then
        # Comment + headers only: collect only .h files from include/
        include_dir="${REPO_ROOT}/include/${subdir}"
        if [ -d "$include_dir" ]; then
            while IFS= read -r -d '' file; do
                ALL_FILES+=("$file")
            done < <(find "$include_dir" -maxdepth 1 -name "*.h" -type f -print0)
        fi
    elif [ "$COMMENT_SELECTED" = true ]; then
        # Comment without headers only: collect both .c and .h files
        # Collect .c files from src/
        src_dir="${REPO_ROOT}/src/${subdir}"
        if [ -d "$src_dir" ]; then
            while IFS= read -r -d '' file; do
                ALL_FILES+=("$file")
            done < <(find "$src_dir" -maxdepth 1 -name "*.c" -type f -print0)
        fi
        # Collect .h files from include/
        include_dir="${REPO_ROOT}/include/${subdir}"
        if [ -d "$include_dir" ]; then
            while IFS= read -r -d '' file; do
                ALL_FILES+=("$file")
            done < <(find "$include_dir" -maxdepth 1 -name "*.h" -type f -print0)
        fi
    else
        # Non-comment templates: collect only .c files from src/
        src_dir="${REPO_ROOT}/src/${subdir}"
        if [ -d "$src_dir" ]; then
            while IFS= read -r -d '' file; do
                ALL_FILES+=("$file")
            done < <(find "$src_dir" -maxdepth 1 -name "*.c" -type f -print0)
        fi
    fi
done

# Sort all files for consistent ordering
mapfile -t ALL_FILES < <(printf '%s\n' "${ALL_FILES[@]}" | sort)

TOTAL_COMMANDS=${#ALL_FILES[@]}

if [ $TOTAL_COMMANDS -eq 0 ]; then
    if [ "$COMMENT_SELECTED" = true ] && [ "$HEADERS_ONLY" = true ]; then
        echo -e "${YELLOW}Warning: No .h files found in selected subdirectories${NC}" >&2
    elif [ "$COMMENT_SELECTED" = true ]; then
        echo -e "${YELLOW}Warning: No .c or .h files found in selected subdirectories${NC}" >&2
    else
        echo -e "${YELLOW}Warning: No .c files found in selected subdirectories${NC}" >&2
    fi
    exit 0
fi

if [ "$COMMENT_SELECTED" = true ] && [ "$HEADERS_ONLY" = true ]; then
    echo -e "${GREEN}Found ${TOTAL_COMMANDS} header files to process${NC}"
elif [ "$COMMENT_SELECTED" = true ]; then
    echo -e "${GREEN}Found ${TOTAL_COMMANDS} files to process (.c and .h files)${NC}"
else
    echo -e "${GREEN}Found ${TOTAL_COMMANDS} files to process (.c files only)${NC}"
fi
echo -e "${YELLOW}Will create windows with 5 splits each${NC}"
echo "Press Enter to start, or Ctrl+C to cancel..."
read -r < /dev/tty

# Configuration: panes per window
PANES_PER_WINDOW=5

# Track current window and pane count
CURRENT_WINDOW=""
PANES_IN_CURRENT_WINDOW=0
WINDOW_NUMBER=0

# Process each file
CURRENT_COMMAND=0
for filepath in "${ALL_FILES[@]}"; do
    ((CURRENT_COMMAND++)) || true
    
    # Generate command
    CMD=$(generate_command "$filepath" "$PROMPT_STRING")
    
    # Extract filename for pane title
    FILENAME=$(basename "$filepath")
    
    # Check if we need a new window
    # First window gets 1 pane (odd), subsequent windows get 5 panes each
    MAX_PANES_FOR_CURRENT_WINDOW=$PANES_PER_WINDOW
    if [ $WINDOW_NUMBER -eq 0 ]; then
        MAX_PANES_FOR_CURRENT_WINDOW=1  # First window: 1 pane only
    fi
    
    if [ -z "$CURRENT_WINDOW" ] || [ $PANES_IN_CURRENT_WINDOW -ge $MAX_PANES_FOR_CURRENT_WINDOW ]; then
        ((WINDOW_NUMBER++)) || true
        WINDOW_NAME="batch-${WINDOW_NUMBER}"
        
        # Create new window (detached, so we don't switch to it)
        CURRENT_WINDOW=$(tmux new-window -d -n "$WINDOW_NAME" -P -F '#{window_id}' "${SHELL:-/bin/bash}")
        PANES_IN_CURRENT_WINDOW=1
        
        echo -e "\n${GREEN}Created new window: ${WINDOW_NAME} (window ${WINDOW_NUMBER})${NC}"
    else
        # Create split in current window
        ((PANES_IN_CURRENT_WINDOW++)) || true
    fi
    
    # Show progress
    echo -e "\n${GREEN}[${CURRENT_COMMAND}/${TOTAL_COMMANDS}]${NC} Adding to ${WINDOW_NAME}: ${YELLOW}${FILENAME}${NC}"
    echo -e "Command: ${CMD}"
    echo -e "${YELLOW}Press Enter to execute this command, or Ctrl+C to stop...${NC}"
    read -r < /dev/tty
    
    # If this is not the first pane in the window, create a split
    if [ $PANES_IN_CURRENT_WINDOW -gt 1 ]; then
        # Create vertical split in current window
        NEW_PANE=$(tmux split-window -h -t "$CURRENT_WINDOW" -P -F '#{pane_id}' "${SHELL:-/bin/bash}")
        
        # Set pane title
        tmux select-pane -t "$NEW_PANE" -T "$FILENAME"
        
        # Evenly distribute all panes horizontally
        tmux select-layout -t "$CURRENT_WINDOW" even-horizontal
        
        # Send command to the new pane
        tmux send-keys -t "$NEW_PANE" "cd '${REPO_ROOT}'" C-m
        sleep 0.1
        tmux send-keys -t "$NEW_PANE" -l "$CMD"
        tmux send-keys -t "$NEW_PANE" C-m
        
        echo -e "${GREEN}Command sent to pane ${NEW_PANE} in window ${WINDOW_NAME}${NC}"
    else
        # First pane in window - just send command
        tmux send-keys -t "$CURRENT_WINDOW" "cd '${REPO_ROOT}'" C-m
        sleep 0.1
        tmux send-keys -t "$CURRENT_WINDOW" -l "$CMD"
        tmux send-keys -t "$CURRENT_WINDOW" C-m
        
        # Set pane title
        tmux select-pane -t "$CURRENT_WINDOW" -T "$FILENAME"
        
        echo -e "${GREEN}Command sent to window ${WINDOW_NAME}${NC}"
    fi
    
done

echo -e "\n${GREEN}All commands have been executed!${NC}"
echo -e "Created ${WINDOW_NUMBER} window(s) with up to ${PANES_PER_WINDOW} panes each"
echo ""
echo "You can switch between windows using:"
echo "  - Ctrl+b then n (next window)"
echo "  - Ctrl+b then p (previous window)"
echo "  - Ctrl+b then <number> (switch to window number)"
echo "  - Ctrl+b then w (list all windows)"
echo ""
echo "Within each window, use:"
echo "  - Ctrl+b then o (cycle through panes)"
echo "  - Ctrl+b then ; (go to last active pane)"
