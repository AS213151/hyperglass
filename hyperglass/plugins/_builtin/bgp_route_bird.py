"""Parse BIRD 'show route all' Response to Structured Data."""

# Standard Library
import typing as t

# Third Party
from pydantic import PrivateAttr

# Project
from hyperglass.log import log
from hyperglass.exceptions.private import ParsingError
from hyperglass.models.parsing.bird import parse_bird

# Local
from .._output import OutputPlugin

if t.TYPE_CHECKING:
    # Project
    from hyperglass.models.data import OutputDataModel
    from hyperglass.models.api.query import Query

    # Local
    from .._output import OutputType


class BGPRoutePluginBird(OutputPlugin):
    """Coerce a BIRD route table text response to a standard BGP Table structure."""

    _hyperglass_builtin: bool = PrivateAttr(True)
    platforms: t.Sequence[str] = ("bird",)
    directives: t.Sequence[str] = (
        "__hyperglass_bird_bgp_route_table__",
        "bird-bgp-community",
        "bird-bgp-aspath",
    )

    def process(self, *, output: "OutputType", query: "Query") -> "OutputType":
        """Parse BIRD response if data is a string (and is therefore unparsed)."""
        should_process = all(
            (
                isinstance(output, (list, tuple)),
                query.device.platform in self.platforms,
                query.device.structured_output is True,
                query.device.has_directives(*self.directives),
            )
        )
        if not should_process:
            return output
        try:
            return parse_bird(output)
        except Exception as err:
            log.bind(error=str(err)).critical("Failed to parse BIRD output")
            raise ParsingError("Error parsing response data") from err
