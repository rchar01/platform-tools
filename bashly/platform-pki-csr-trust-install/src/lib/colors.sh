enable_auto_colors() {
  if [[ -z ${NO_COLOR+x} && ! -t 1 ]]; then NO_COLOR=1; fi
}
print_in_color() {
  local color=$1
  shift
  if [[ ${NO_COLOR:-} == '' ]]; then printf "$color%b\e[0m\n" "$*"; else printf '%b\n' "$*"; fi
}
green() { print_in_color "\e[32m" "$*"; }
blue() { print_in_color "\e[34m" "$*"; }
magenta() { print_in_color "\e[35m" "$*"; }
cyan() { print_in_color "\e[36m" "$*"; }
bold() { print_in_color "\e[1m" "$*"; }
