import unidecode
import re


def slugify(name):
	return re.sub(r'[\W_]+', '-', unidecode.unidecode(name).lower()).strip('-')