
OBJ = ipproof

LANG = de

OBJ_SRC = $(addsuffix .tex,$(OBJ))
OBJ_PDF = $(addsuffix .pdf,$(OBJ))
OBJ_PS  = $(addsuffix .ps,$(OBJ))
OBJ_DVI = $(addsuffix .dvi,$(OBJ))
OBJ_AUX = $(addsuffix .aux,$(OBJ))
HANDOUT_OBJ = $(addsuffix -handout,$(OBJ))
HANDOUT_PDF = $(addsuffix .pdf,$(HANDOUT_OBJ))

SUBDIRS := images

all: $(OBJ_PDF)
pdf: $(OBJ_PDF)
ps:  $(OBJ_PS)
dvi: $(OBJ_DVI)
handout: $(HANDOUT_PDF)

$(OBJ_DVI): $(OBJ_SRC) 
	latex $(OBJ_SRC)
	bibtex $(OBJ_AUX) || true
	latex $(OBJ_SRC)
	latex $(OBJ_SRC)

$(OBJ_PS): $(OBJ_DVI)
	dvips -o${OBJ_PS} $(OBJ_DVI)

$(OBJ_PDF): $(OBJ_SRC)
	@for dir in $(SUBDIRS); do \
		 echo "### Entering $$dir" && cd $$dir && $(MAKE) && cd ..; \
	done
	pdflatex $(OBJ_SRC)
	bibtex $(OBJ_AUX) || true
	pdflatex $(OBJ_SRC)

preview: $(OBJ_PDF)
	xpdf -fullscreen -papercolor white -bg black \
		 $(OBJ_PDF) 1>/dev/null 2>&1 &

spellcheck: $(OBJ_SRC)
	aspell --mode=tex --ignore=3 --lang=$(LANG) -c $(OBJ_SRC)


$(HANDOUT_PDF):	$(OBJ_SRC)
		pdfnup --nup "2x3" --offset ".25cm .25cm" --delta ".25cm .5cm" --frame true --scale 0.9 --outfile $(HANDOUT_PDF).tmp.pdf  $(OBJ_PDF)
		mv $(HANDOUT_PDF).tmp.pdf  $(HANDOUT_PDF) 

clean:
	@for dir in $(SUBDIRS); do \
		 echo "### Entering $$dir" && cd $$dir && $(MAKE) clean && cd ..; \
	done
	rm -f *.aux *.idx *.log *.out *.toc *.bbl *.blg \
		  *.dvi *.ps *.lot *.pdf *.tmp *.bak *~

.PHONY: all clean


# vim600: fdm=marker tw=120 sw=4 ts=4 sts=4 ff=unix noet:
