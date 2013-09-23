
SUBDIRS = svg

all clean:
	@for dir in $(SUBDIRS); do \
		(cd $$dir && $(MAKE) $@); \
	done
