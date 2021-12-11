from typing import Union, Optional, List

from asn1crypto import x509, cms, core


def extract_dir_name(names: x509.GeneralNames,
                     err_msg_prefix: str) -> x509.Name:
    try:
        name: x509.Name = next(
            gname.chosen for gname in names
            if gname.name == 'directory_name'
        )
    except StopIteration:
        raise NotImplementedError(
            f"{err_msg_prefix}; only distinguished names are supported, "
            f"and none were found."
        )
    return name.untag()


def extract_ac_issuer_dir_name(attr_cert: cms.AttributeCertificateV2) \
        -> x509.Name:
    issuer_rec = attr_cert['ac_info']['issuer']
    if issuer_rec.name == 'v1_form':
        aa_names = issuer_rec.chosen
    else:
        issuerv2: cms.V2Form = issuer_rec.chosen
        if not isinstance(issuerv2['issuer_name'], core.Void):
            aa_names = issuerv2['issuer_name']
        else:
            aa_names = x509.GeneralNames([])
    return extract_dir_name(aa_names, "Could not extract AC issuer name")


def issuer_serial(cert: Union[x509.Certificate, cms.AttributeCertificateV2]) \
        -> bytes:
    if isinstance(cert, x509.Certificate):
        return cert.issuer_serial
    else:
        issuer_name = extract_ac_issuer_dir_name(cert)
        result_bytes = b'%s:%d' % (
            issuer_name.sha256, cert['ac_info']['serial_number'].native
        )
        return result_bytes


def get_ac_extension_value(attr_cert: cms.AttributeCertificateV2,
                           ext_name: str):
    try:
        return next(
            ext['extn_value'].parsed
            for ext in attr_cert['ac_info']['extensions']
            if ext['extn_id'].native == ext_name
        )
    except StopIteration:
        return None


def _get_absolute_http_crls(dps: Optional[x509.CRLDistributionPoints]):
    # see x509._get_http_crl_distribution_points

    if dps is None:
        return

    for distribution_point in dps:
        distribution_point_name = distribution_point['distribution_point']
        if isinstance(distribution_point_name, core.Void):
            continue
        # RFC 5280 indicates conforming CA should not use the relative form
        if distribution_point_name.name == 'name_relative_to_crl_issuer':
            continue
        # This library is currently only concerned with HTTP-based CRLs
        for general_name in distribution_point_name.chosen:
            if general_name.name == 'uniform_resource_identifier':
                yield distribution_point


def _get_ac_crl_dps(attr_cert: cms.AttributeCertificateV2) \
        -> List[x509.DistributionPoint]:
    dps_ext = get_ac_extension_value(attr_cert, 'crl_distribution_points')
    return list(_get_absolute_http_crls(dps_ext))


def _get_ac_delta_crl_dps(attr_cert: cms.AttributeCertificateV2) \
        -> List[x509.DistributionPoint]:
    delta_dps_ext = get_ac_extension_value(attr_cert, 'freshest_crl')
    return list(_get_absolute_http_crls(delta_dps_ext))


def get_relevant_crl_dps(
        cert: Union[x509.Certificate, cms.AttributeCertificateV2],
        *, use_deltas) -> List[x509.DistributionPoint]:
    is_pkc = isinstance(cert, x509.Certificate)

    if is_pkc:
        # FIXME: This utility property in asn1crypto is not precise enough.
        #  More to the point, URLs attached to the same distribution point
        #  are considered interchangeable, but URLs belonging to different
        #  distribution points very much aren't---different distribution points
        #  can differ in what reason codes they record, etc.
        # For the time being, we'll assume that people who care about that sort
        # of nuance will run in 'require' mode, in which case the validator
        # should complain if the available CRLs don't cover all reason codes.
        sources = list(cert.crl_distribution_points)
    else:
        sources = _get_ac_crl_dps(cert)
    if use_deltas:
        if is_pkc:
            sources.extend(cert.delta_crl_distribution_points)
        else:
            sources.extend(_get_ac_delta_crl_dps(cert))

    return sources