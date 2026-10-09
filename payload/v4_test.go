package payload_test

import "fmt"

// v4 assembles an address from numbers instead of writing it as a literal.
// The reason is the plugin itself: a session that develops it runs through
// it, so a value written as a literal can arrive on disk in another form,
// while one built at run time cannot. The tests taken over from the external
// test lab keep that habit.
func v4(a, b, c, d int) string { return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d) }
