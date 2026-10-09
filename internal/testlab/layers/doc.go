// Package layers probes the interplay of the detection layers: what
// detect.NewComposite does when two layers report hits over the same text,
// which of them wins, and what an excluded hit does to the layers behind it.
// The layers themselves are covered elsewhere; here only their meeting
// points are.
package layers
