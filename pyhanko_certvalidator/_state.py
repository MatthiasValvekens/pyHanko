from dataclasses import dataclass
from typing import Optional


@dataclass
class ValProcState:
    path_len: int
    """
    Length of the path being validated.
    
    .. note::
        This is the path length in the sense of RFC 5280, i.e.
        the root doesn't count.
    """
    is_side_validation: bool

    index: int = 0
    ee_name_override: Optional[str] = None

    @property
    def is_ee_cert(self) -> bool:
        return self.index == self.path_len

    def describe_cert(self, def_interm=False):
        """
        :return:
            A unicode string describing the position of a certificate in the chain
        """

        if self.index < 1 and self.ee_name_override is None:
            # catchall default
            return "the certificate"
        elif not self.is_ee_cert:
            return (
                f'{"the " if def_interm else ""}intermediate '
                f'certificate {self.index}'
            )

        if self.ee_name_override is not None:
            return 'the ' + self.ee_name_override

        return 'the end-entity certificate'
