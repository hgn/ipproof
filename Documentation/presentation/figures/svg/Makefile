
SVG_FILES = $(wildcard *.svg)
PDF_FILES = $(patsubst %.svg,%.pdf,  $(SVG_FILES))

all: $(PDF_FILES)


%.pdf: %.svg 
	@ echo "convert "$<
	inkscape --without-gui --export-text-to-path \
					--export-pdf=$*.pdf $*.svg


clean:
	rm -rf *.pdf
