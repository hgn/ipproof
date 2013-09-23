
OBJ = ipproof-introduction

LANG = de

OBJ_SRC = $(addsuffix .tex,$(OBJ))
OBJ_PDF = $(addsuffix .pdf,$(OBJ))
OBJ_PS  = $(addsuffix .ps,$(OBJ))
OBJ_DVI = $(addsuffix .dvi,$(OBJ))
OBJ_AUX = $(addsuffix .aux,$(OBJ))
OBJ_HANDOUT_PDF = $(addsuffix -handout.pdf,$(OBJ))

all: $(OBJ_PDF)
pdf: $(OBJ_PDF)
ps:  $(OBJ_PS)
dvi: $(OBJ_DVI)

$(OBJ_DVI): $(OBJ_SRC) 
	latex $(OBJ_SRC)
	bibtex $(OBJ_AUX) || true
	latex $(OBJ_SRC)
	latex $(OBJ_SRC)

$(OBJ_PS): $(OBJ_DVI)
	dvips -o${OBJ_PS} $(OBJ_DVI)

$(OBJ_PDF): $(OBJ_SRC)
	cd figures && $(MAKE)
	pdflatex $(OBJ_SRC)
	pdflatex $(OBJ_SRC)
	@echo
	@ls -alh $(OBJ_PDF) | cut -d ' ' -f 5,8

preview: $(OBJ_PDF)
	xpdf -fullscreen $(OBJ_PDF) 1>/dev/null 2>&1 &

spellcheck: $(OBJ_SRC)
	aspell --mode=tex --ignore=3 --lang=$(LANG) -c $(OBJ_SRC)

clean:
	cd figures && $(MAKE) clean
	rm -f *.aux *.idx *.log *.out *.toc *.bbl *.blg \
		  *.dvi *.ps *.lot *.pdf *.tmp *.bak *~ core *.nav *.snm *.vrb

handout: $(OBJ_PDF)
	pdfnup --nup "2x2" --offset ".25cm .25cm" --delta ".25cm .5cm" --frame true --scale 0.9 --outfile $(OBJ_HANDOUT_PDF)   $(OBJ_PDF)

.PHONY: all clean


# vim600: fdm=marker tw=120 sw=4 ts=4 sts=4 ff=unix noet:
