from . import generic


class PdfHandler:

    def get_object(self, ido: generic.IndirectObject):
        raise NotImplementedError

    @property
    def root_ref(self) -> generic.IndirectObject:
        raise NotImplementedError

    @property
    def root(self):
        return self.root_ref.get_object()

    # TODO write tests specifically for this helper function
    def _walk_page_tree(self, page_ix, retrieve_parent):

        # the spec says that this will always be an indirect reference
        page_tree_root_ref = self.root.raw_get('/Pages')
        assert isinstance(page_tree_root_ref, generic.IndirectObject)
        page_tree_root = page_tree_root_ref.get_object()
        try:
            root_resources = page_tree_root['/Resources']
        except KeyError:
            root_resources = generic.DictionaryObject()

        page_count = page_tree_root['/Count']
        if not (0 <= page_ix < page_count):
            raise ValueError('Page index out of range')

        def _recurse(first_page_ix, pages_obj_ref, last_rsrc_dict,
                     prev_last_indir):
            pages_obj = pages_obj_ref.get_object()
            kids = pages_obj.raw_get('/Kids')
            if isinstance(kids, generic.IndirectObject):
                kids = kids.get_object()

            try:
                last_rsrc_dict = pages_obj.raw_get('/Resources')
            except KeyError:
                pass

            cur_page_ix = first_page_ix
            for kid_index, kid_ref in enumerate(kids):
                # If this is not the case, the child node cannot possibly have
                # a valid /Parent entry either, so let's assume that nobody
                # screws up their PDF generator THAT badly
                assert isinstance(kid_ref, generic.IndirectObject)

                kid = kid_ref.get_object()

                node_type = kid['/Type']
                if node_type == '/Pages':
                    # recurse into this branch if the page we need
                    # is part of it
                    desc_count = kid['/Count']
                    if cur_page_ix <= page_ix < cur_page_ix + desc_count:
                        return _recurse(
                            cur_page_ix, kid_ref, last_rsrc_dict,
                            kid_ref
                        )
                    cur_page_ix += desc_count
                elif node_type == '/Page':
                    if cur_page_ix == page_ix:
                        if retrieve_parent:
                            return (
                                pages_obj_ref, kid_index, last_rsrc_dict,
                                # we want to ignore the potential reference to
                                # /Kids in this case
                                prev_last_indir
                            )
                        else:
                            try:
                                last_rsrc_dict = kid.raw_get('/Resources')
                            except KeyError:
                                pass
                            return kid_ref, last_rsrc_dict
                    else:
                        cur_page_ix += 1
            # This means the PDF is not standards-compliant
            raise ValueError('Page not found')

        return _recurse(
            0, page_tree_root_ref, root_resources, page_tree_root_ref
        )

    def find_page_container(self, page_ix):
        """
        Retrieve the node in the page tree containing the
        page with index page_ix, along with the necessary objects to modify it
        in an incremental update scenario.

        :param page_ix:
            The (zero-indexed) number of the page for which we want to
            retrieve the parent.
        :return:
            A quadruple with the /Pages object (or a reference to it),
            the index of the target page in said /Pages object,
            (possibly inherited) resource dictionary, and a reference
            to the object that needs to be marked for an update
            if the /Pages object is updated.
        """
        return self._walk_page_tree(page_ix, retrieve_parent=True)

    def find_page_for_modification(self, page_ix):
        """
        Retrieve the page with index page_ix from the page tree, along with
        the necessary objects to modify it in an incremental update scenario.

        :param page_ix:
            The (zero-indexed) number of the page to retrieve.
        :return:
            A with a reference to the page object and a
            (possibly inherited) resource dictionary.
        """
        return self._walk_page_tree(page_ix, retrieve_parent=False)
