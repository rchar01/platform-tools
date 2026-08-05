validate_not_empty() {
  [[ -n $1 ]] || printf '%s\n' 'must not be empty'
}

validate_format() {
  case $1 in
    text|json) ;;
    *) printf 'Format must be text or json: %s\n' "$1" ;;
  esac
}
