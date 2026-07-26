validate_not_empty() {
  [[ -n $1 ]] || printf '%s\n' 'must not be empty'
}
