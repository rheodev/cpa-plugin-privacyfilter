package payload

// Roles returns the role of every element of the messages array of body,
// in order, with "" for an element that is no object or has no string
// role, and nil when body has no messages array. The forward pass needs
// the roles to tell the model's own turns from the user's side; the walk
// itself reports paths, and a path names the message by index. body must
// be valid JSON, as Walk checks.
func Roles(body []byte) []string {
	start, end, err := findValue(body, Path{"messages"})
	if err != nil || start >= end || body[start] != '[' {
		return nil
	}
	var roles []string
	i := skipWS(body, start+1)
	for i < end && body[i] != ']' {
		elemStart := i
		elemEnd, err := skipValue(body, i)
		if err != nil {
			return roles
		}
		role := ""
		if body[elemStart] == '{' {
			if rs, re, err := findFrom(body, elemStart, Path{"role"}); err == nil && re <= elemEnd {
				if s, err := decodeString(body[rs:re]); err == nil {
					role = s
				}
			}
		}
		roles = append(roles, role)
		i = skipWS(body, elemEnd)
		if i < end && body[i] == ',' {
			i = skipWS(body, i+1)
		}
	}
	return roles
}
