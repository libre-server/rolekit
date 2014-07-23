EXTRA_DIST = server_role_states.dot

graphs = server_role_states.png

all: graphviz

graphviz: $(graphs)

SUFFIXES = .dot .png
.dot.png:
	dot -T png -o $@ $<

clean-local:
	rm -f $(graphs)
