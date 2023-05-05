NODEENV_CONFIG := ./utils/nodeenv.ini
NODEENV_REQ    := ./utils/nodeenv-requirements.txt
MODULES        := \
	contracts


all: build/nodeenv.state $(MODULES)


build/nodeenv.state: $(NODEENV_CONFIG) $(NODEENV_REQ)
	which nodeenv || (echo "ERROR: nodeenv is not installed" && exit 1)
	nodeenv \
		--config=$(NODEENV_CONFIG) \
		--requirements=$(NODEENV_REQ) \
		build/nodeenv
	touch $@


$(MODULES):
	$(MAKE) -C $@


$(addprefix clean_,$(MODULES)):
	$(MAKE) -C $(subst clean_,,$@) clean


clean: $(addprefix clean_,$(MODULES))
	rm -rf build/nodeenv build/nodeenv.state


.PHONY: all clean $(MODULES) $(addprefix clean_,$(MODULES))
