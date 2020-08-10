import codecs
from PyPDF2 import generic

__all__ = ['pdf_name', 'pdf_string']

pdf_name = generic.NameObject
pdf_string = generic.createStringObject
