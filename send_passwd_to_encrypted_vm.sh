#!/usr/bin/env bash

# send_passwd_to_encrypted_vm.sh
#
# Normally, when the VM’s operating system is running, spice-vdagent intercepts keyboard shortcuts and allows you to paste text (for example, using `CTRL+SHIFT+V`).
# The problem arises when the disk is encrypted: at this stage, the operating system hasn’t booted yet, so `spice-vdagent` isn’t active and there’s no channel for direct pasting.
# To work around this limitation, I created a small script that takes the VM name as the first parameter and a string as the second. The script sends the string character by character to the VM using `virsh send-key`.
# After a few seconds, the password is automatically typed in, and at the end, the script also presses the `Enter` key.

VM="$1"
TEXT="$2"
HOLDTIME=150  # ms for each key

if [[ -z "$VM" || -z "$TEXT" ]]; then
  echo "Usage: $0 <VM-name> <passwd>"
  exit 1
fi

declare -A MAP=(
  ["a"]="KEY_A" ["b"]="KEY_B" ["c"]="KEY_C" ["d"]="KEY_D" ["e"]="KEY_E"
  ["f"]="KEY_F" ["g"]="KEY_G" ["h"]="KEY_H" ["i"]="KEY_I" ["j"]="KEY_J"
  ["k"]="KEY_K" ["l"]="KEY_L" ["m"]="KEY_M" ["n"]="KEY_N" ["o"]="KEY_O"
  ["p"]="KEY_P" ["q"]="KEY_Q" ["r"]="KEY_R" ["s"]="KEY_S" ["t"]="KEY_T"
  ["u"]="KEY_U" ["v"]="KEY_V" ["w"]="KEY_W" ["x"]="KEY_X" ["y"]="KEY_Y"
  ["z"]="KEY_Z"

  ["A"]="KEY_LEFTSHIFT KEY_A" ["B"]="KEY_LEFTSHIFT KEY_B" ["C"]="KEY_LEFTSHIFT KEY_C"
  ["D"]="KEY_LEFTSHIFT KEY_D" ["E"]="KEY_LEFTSHIFT KEY_E" ["F"]="KEY_LEFTSHIFT KEY_F"
  ["G"]="KEY_LEFTSHIFT KEY_G" ["H"]="KEY_LEFTSHIFT KEY_H" ["I"]="KEY_LEFTSHIFT KEY_I"
  ["J"]="KEY_LEFTSHIFT KEY_J" ["K"]="KEY_LEFTSHIFT KEY_K" ["L"]="KEY_LEFTSHIFT KEY_L"
  ["M"]="KEY_LEFTSHIFT KEY_M" ["N"]="KEY_LEFTSHIFT KEY_N" ["O"]="KEY_LEFTSHIFT KEY_O"
  ["P"]="KEY_LEFTSHIFT KEY_P" ["Q"]="KEY_LEFTSHIFT KEY_Q" ["R"]="KEY_LEFTSHIFT KEY_R"
  ["S"]="KEY_LEFTSHIFT KEY_S" ["T"]="KEY_LEFTSHIFT KEY_T" ["U"]="KEY_LEFTSHIFT KEY_U"
  ["V"]="KEY_LEFTSHIFT KEY_V" ["W"]="KEY_LEFTSHIFT KEY_W" ["X"]="KEY_LEFTSHIFT KEY_X"
  ["Y"]="KEY_LEFTSHIFT KEY_Y" ["Z"]="KEY_LEFTSHIFT KEY_Z"

  ["0"]="KEY_0" ["1"]="KEY_1" ["2"]="KEY_2" ["3"]="KEY_3"
  ["4"]="KEY_4" ["5"]="KEY_5" ["6"]="KEY_6" ["7"]="KEY_7"
  ["8"]="KEY_8" ["9"]="KEY_9"

  ["!"]="KEY_LEFTSHIFT KEY_1" ["@"]="KEY_LEFTSHIFT KEY_2"
  ["#"]="KEY_LEFTSHIFT KEY_3" ["$"]="KEY_LEFTSHIFT KEY_4"
  ["%"]="KEY_LEFTSHIFT KEY_5" ["^"]="KEY_LEFTSHIFT KEY_6"
  ["&"]="KEY_LEFTSHIFT KEY_7" ["*"]="KEY_LEFTSHIFT KEY_8"
  ["("]="KEY_LEFTSHIFT KEY_9" [")"]="KEY_LEFTSHIFT KEY_0"

  ["-"]="KEY_MINUS" ["_"]="KEY_LEFTSHIFT KEY_MINUS"
  ["="]="KEY_EQUAL" ["+"]="KEY_LEFTSHIFT KEY_EQUAL"
  ["["]="KEY_LEFTBRACE" ["{"]="KEY_LEFTSHIFT KEY_LEFTBRACE"
  ["]"]="KEY_RIGHTBRACE" ["}"]="KEY_LEFTSHIFT KEY_RIGHTBRACE"
  ["\\"]="KEY_BACKSLASH" ["|"]="KEY_LEFTSHIFT KEY_BACKSLASH"
  [";"]="KEY_SEMICOLON" [":"]="KEY_LEFTSHIFT KEY_SEMICOLON"
  ["'"]="KEY_APOSTROPHE" ["\""]="KEY_LEFTSHIFT KEY_APOSTROPHE"
  [","]="KEY_COMMA" ["<"]="KEY_LEFTSHIFT KEY_COMMA"
  ["."]="KEY_DOT" [">"]="KEY_LEFTSHIFT KEY_DOT"
  ["/"]="KEY_SLASH" ["?"]="KEY_LEFTSHIFT KEY_SLASH"
  ["\`"]="KEY_GRAVE" ["~"]="KEY_LEFTSHIFT KEY_GRAVE"
  [" "]="KEY_SPACE"
)

for (( i=0; i<${#TEXT}; i++ )); do
  c="${TEXT:$i:1}"
  seq="${MAP[$c]}"

  if [[ -z "$seq" ]]; then
    echo "Character is not supported: '$c'"
    exit 2
  fi

  read -ra keys <<< "$seq"
  sudo virsh send-key "$VM" --holdtime "$HOLDTIME" "${keys[@]}"
  sleep 1
done

sudo virsh send-key "$VM" --holdtime "$HOLDTIME" KEY_ENTER
