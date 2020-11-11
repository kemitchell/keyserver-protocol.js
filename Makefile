diagram.svg: diagram.dot
	dot -Tsvg $< > $@
