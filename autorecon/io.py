import string
import sys


def e(*args, frame_index=1, **kvargs):
	frame = sys._getframe(frame_index)

	vals = {}

	vals.update(frame.f_globals)
	vals.update(frame.f_locals)
	vals.update(kvargs)

	return string.Formatter().vformat(' '.join(args), args, vals)
