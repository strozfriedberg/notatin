from typing import Optional

# classes
class PyNotatinParser(object):
    """ Create and return a new object. """
    @staticmethod # known case of __new__
    def __new__(FileOrFileLike) -> PyNotatinParser: ...

    """ Returns the key for the `path` parameter """
    def open(self, path: str) -> PyNotatinKey: ...

    """ Returns an iterator that yields reg keys """
    def reg_keys(self): ...

    """ Returns the root key """
    def root(self) -> PyNotatinKey: ...

    """ Returns the parent key for the `key` parameter """
    def get_parent(self, key: PyNotatinKey) -> PyNotatinKey: ...

class PyNotatinKey(object):
    """ Returns an iterator that yields reg values """
    def values(self): ...

    """ Returns the requested value, or None """
    def value(self, name: str) -> Optional[PyNotatinValue]: ...

    """ Returns an iterator that yields sub keys """
    def subkeys(self, parser: PyNotatinParser): ...

    """ Returns the requested key, or None """
    def find_key(self, parser: PyNotatinParser, path: str) -> Optional[PyNotatinKey]: ...

    """ Returns the name of the key """
    @property
    def name(self) -> str: ...

    """ Returns the path of the key """
    @property
    def path(self) -> str: ...

    """ Returns the number of sub keys """
    @property
    def number_of_sub_keys(self) -> int: ...

    """ Returns the number of key values """
    @property
    def number_of_key_values(self) -> int: ...

class PyNotatinValue(object):
    """ Returns the value as bytes """
    @property
    def value(self) -> bytes: ...

    """ Returns the name of the value, or "(default)" for the default value """
    @property
    def pretty_name(self) -> str: ...

    """ Returns the name of the value """
    @property
    def name(self) -> str: ...

    """ Returns the data type as an integer """
    @property
    def raw_data_type(self) -> int: ...

    """ Returns the value as typed data """
    @property
    def content(self) -> object: ...

    """ Decodes the content using one of the supported decoders (see `PyNotatinDecodeFormat`) """
    def decode(self, format: PyNotatinDecodeFormat, offset: int) -> PyNotatinContent: ...

class PyNotatinContent(object):
    """ Returns the decoded content """
    @property
    def content(self) -> object: ...

    """ Decodes the content using one of the supported decoders (see `PyNotatinDecodeFormat`).
        This method allows for chaining of decode operations """
    def decode(self,format: PyNotatinDecodeFormat, offset: int) -> PyNotatinContent: ...

class PyNotatinDecodeFormat(object):
    lznt1: PyNotatinDecodeFormat
    """ Returns an lznt1 decoder """

    rot13: PyNotatinDecodeFormat
    """ Returns a rot13 decoder """

    utf16_multiple: PyNotatinDecodeFormat
    """ Returns a utf16_multiple (REG_MULTI_SZ) decoder """

    utf16: PyNotatinDecodeFormat
    """ Returns a utf16 decoder """

class PyNotatinParserBuilder(object):
    """ Create and return a new object. """
    @staticmethod # known case of __new__
    def __new__(FileOrFileLike) -> PyNotatinParserBuilder: ...

    """ Set to true to search for deleted and modified items """
    def recover_deleted(self, recover: bool): ...

    """ Add a transaction log file """
    def with_transaction_log(self, FileOrFileLike): ...

    """ Returns a PyNotatinParser """
    def build(self) -> PyNotatinParser: ...
