validate_not_empty() {
  [[ -n $1 ]] || printf '%s\n' 'must not be empty'
}

validate_days() {
  if [[ ! $1 =~ ^[0-9]+$ ]]; then
    printf 'Days value must be numeric: %s\n' "$1"
  elif (( $1 < 1 )); then
    printf 'Days value must be at least 1: %s\n' "$1"
  fi
}
