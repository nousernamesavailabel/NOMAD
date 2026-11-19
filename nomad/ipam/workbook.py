"""Writing networks out as pages of an addressing workbook, laid out like the tribe's (so the spreadsheet can be kept
up to date from IPAM, and imports back as it went out).

Each network becomes a page:
    a header row (the enclave or "Network Name", Telephony Rng, Subnet, Mask, Gateway, Reserved, Assignment, then any
    other subnet details),
    the unit row: unit | location | revision date | revision,
    the summary, a row per subnet,
    "Unit Base Info" with the network's other details,
    "Detailed Info": each subnet again, address by address (every address, for subnets up to 256; otherwise the
    recorded ones), with Y under Reserved and the name under Assignment,
    "End".
The layout has no place for an address's MAC or description (the CSV export has them). A used address with no name
is written as "In use", since the importer skips rows with neither a Y nor a name.

csv_rows() is the IP Addresses page's other export, Export to CSV. Both are made only from IPAM's networks, subnets
and addresses, and tests/test_export_format.py holds them to their saved layout: what the VLANs and Subnet Placement
pages keep about a subnet stays in their own tables, never in a subnet's details (which would become columns here).
"""
import re

from .store import RESERVED, STATUSES

LIST_EVERY_ADDRESS_UP_TO = 256  # Larger subnets list only their recorded addresses (and the gateway)
TELEPHONY = "Telephony Rng"
UNIT_FIELDS = ["Unit", "Location", "Revision date", "Revision"]
NOT_BASE_INFO = set(UNIT_FIELDS) | {"Enclave", "Imported from"}
HOST_ROUTE_MASKS = {4: "255.255.255.255", 6: "/128"}
UNNAMED_USED = "In use"
CSV_COLUMNS = ["Subnet", "Subnet Name", "Gateway", "Address", "Status", "Name", "MAC Address", "Description",
               "Last Changed", "Changed By"]
BAD_TITLE_CHARACTERS = re.compile(r"[\[\]:*?/\\]")


def _name(subnet):
    """The subnet's name, or its CIDR if it has none: a Detailed Info section starts at a named row."""
    return subnet.name or subnet.cidr


def _mask(block):
    return str(block.netmask) if block.version == 4 else f"/{block.prefixlen}"


def _title(network, taken):
    """A page title: the network's name (Excel allows 31 characters). Not the page it was imported from: units are
    often imported from pages all called the same thing (\"Network Template\"), so every page came out alike."""
    title = BAD_TITLE_CHARACTERS.sub("-", network.name).strip()[:31] or "Network"
    base, number = title, 2
    while title.casefold() in taken:
        suffix = f" ({number})"
        title = base[:31 - len(suffix)] + suffix
        number += 1
    taken.add(title.casefold())
    return title


def page_rows(store, network):
    """The page for one network, as rows of cell values (column A left empty, as in the tribe's workbooks)."""
    subnets = store.subnets(network.id)
    addresses = {address.address: address for address in store.addresses(network.id)}
    details = []  # Subnet detail columns after Assignment, in the order first met
    for subnet in subnets:
        for name in subnet.fields:
            if name != TELEPHONY and name not in details:
                details.append(name)
    name_header = network.fields.get("Enclave") or "Network Name"
    rows = [["", name_header, TELEPHONY, "Subnet", "Mask", "Gateway", "Reserved", "Assignment"] + details]

    def row(name="", telephony="", subnet="", mask="", gateway="", reserved="", assignment="", fields=None):
        return ["", name, telephony, subnet, mask, gateway, reserved, assignment] + \
            [(fields or {}).get(detail, "") for detail in details]

    if any(network.fields.get(name) for name in UNIT_FIELDS):
        # Unit, location and revision date from column B, the revision under Reserved (clear of the Mask column,
        # which would make it read as a subnet)
        unit, location, date, revision = (network.fields.get(name, "") for name in UNIT_FIELDS)
        rows.append(["", unit, location, date, "", "", revision])
    for subnet in subnets:
        block = subnet.network
        rows.append(row(_name(subnet), subnet.fields.get(TELEPHONY, ""), str(block.first), _mask(block), subnet.gateway,
                        "", subnet.description, subnet.fields))
    base = [(name, value) for name, value in network.fields.items() if name not in NOT_BASE_INFO]
    rows += [[], ["", "Unit Base Info"]] + [["", name, value] for name, value in base]
    rows += [[], ["", "Detailed Info"]]
    for subnet in subnets:
        rows += _detail_rows(subnet, subnets, addresses, row)
    rows.append(["", "End"])
    return rows


def _detail_rows(subnet, subnets, addresses, row):
    """A subnet's Detailed Info: its first row names it; the rest are its addresses."""
    block = subnet.network
    nested = [other.network for other in subnets if other.id != subnet.id and other.network.version == block.version
              and other.network.subnet_of(block) and other.network != block]
    telephony = subnet.fields.get(TELEPHONY, "")

    def entry(address, mask):
        # An address in a subnet inside this one is listed there (a block's first row can be one: not twice)
        record = addresses.get(address) if not any(address in inner for inner in nested) else None
        reserved = "Y" if record is not None and record.status == RESERVED else ""
        name = record.name if record is not None else ""
        if record is not None and not name and not reserved:
            name = UNNAMED_USED
        gateway = str(address) if subnet.gateway and str(address) == subnet.gateway else ""
        return str(address), mask, gateway, reserved, name

    if subnet.loopbacks:
        # Host routes: every address its own /32, first to last (the importer finds the range from these rows)
        mask = HOST_ROUTE_MASKS[block.version]
        listed = _addresses_to_list(block, nested, addresses, subnet, every_first_last=True)
        first = entry(listed[0], mask)
        rows = [row(_name(subnet), telephony, first[0], mask, "", first[3], first[4], subnet.fields)]
        rows += [row("", "", *entry(address, mask)) for address in listed[1:]]
        return rows

    mask = _mask(block)
    regular = block.version == 4 and block.num_addresses > 2
    # The network and broadcast rows say so, unless an address is recorded there (a mistake, but kept)
    first, last = entry(block.first, mask), entry(block.last, mask)
    rows = [row(_name(subnet), telephony, first[0], mask, first[2],
                first[3] if first[4] or not regular else "Y", first[4] or ("Network" if regular else ""),
                subnet.fields)]
    listed = [address for address in _addresses_to_list(block, nested, addresses, subnet)
              if address != block.first and (not regular or address != block.last)]
    rows += [row("", "", *entry(address, mask)) for address in listed]
    if regular:
        rows.append(row("", "", last[0], mask, last[2], last[3] if last[4] else "Y", last[4] or "Broadcast"))
    return rows


def _addresses_to_list(block, nested, addresses, subnet, every_first_last=False):
    """The addresses a subnet's Detailed Info lists: every one in a small subnet (except those in a subnet inside
    it), or else just the recorded ones and the gateway."""
    def outside_nested(address):
        return not any(address in inner for inner in nested)

    if block.num_addresses <= LIST_EVERY_ADDRESS_UP_TO and not nested:
        first = int(block.first)
        return [type(block.first)(first + offset) for offset in range(block.num_addresses)]
    chosen = {address for address in addresses if address in block and outside_nested(address)}
    if subnet.gateway:
        gateway = type(block.first)(subnet.gateway)
        chosen.add(gateway)
    chosen.add(block.first)
    if every_first_last:
        chosen.add(block.last)
    return sorted(chosen)


def outside_subnets(store, network):
    """Recorded addresses in no subnet: the workbook layout has nowhere to put them."""
    subnets = [subnet.network for subnet in store.subnets(network.id)]
    return [address for address in store.addresses(network.id)
            if not any(address.address in block for block in subnets)]


def export_workbook(path, networks):
    """Write [(store, network)] to an .xlsx workbook, a page per network. Returns the page titles."""
    from openpyxl import Workbook
    from openpyxl.styles import Font

    workbook = Workbook()
    workbook.remove(workbook.active)
    titles, taken = [], set()
    bold = Font(bold=True)
    for store, network in networks:
        sheet = workbook.create_sheet(_title(network, taken))
        titles.append(sheet.title)
        for values in page_rows(store, network):
            sheet.append([value if value != "" else None for value in values])
        for cell in sheet[1]:
            cell.font = bold
        for row in sheet.iter_rows(min_row=2):
            if row[1].value in ("Unit Base Info", "Detailed Info", "End"):
                row[1].font = bold
        for column, width in zip("ABCDEFGH", (2, 40, 14, 18, 18, 18, 10, 40)):
            sheet.column_dimensions[column].width = width
        sheet.freeze_panes = "A2"
    workbook.save(path)
    return titles


def csv_rows(store, network_id, subnets):
    """Export to CSV: the column names, a row per subnet, then a row per address with the smallest subnet holding it."""
    rows = [list(CSV_COLUMNS)]
    for subnet in subnets:
        rows.append([subnet.cidr, subnet.name, subnet.gateway, "", "", "", "", subnet.description, subnet.modified,
                     subnet.modified_by])
    for address in store.addresses(network_id):
        holding = [subnet for subnet in subnets if address.address in subnet.network]
        subnet = max(holding, key=lambda subnet: (subnet.network.prefixlen, subnet.network.first), default=None)
        rows.append([subnet.cidr if subnet else "", subnet.name if subnet else "", "", address.ip,
                     STATUSES.get(address.status, address.status), address.name, address.mac, address.description,
                     address.modified, address.modified_by])
    return rows
