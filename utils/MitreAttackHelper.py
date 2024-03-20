import MitreCollectionHelper as mh
import ToFileUtils as tfu
from mitreattack.stix20 import MitreAttackData
from stix2 import parse, Campaign

DEFAULT_ENTERPRISE_FILE_PATH = "../files/enterprise-attack"
mitre_attack_data = MitreAttackData(DEFAULT_ENTERPRISE_FILE_PATH)


def get_file():
    """ Metodo per ricavare uno Stix JSON e salvarlo su file """
    strix_json = mh.get_stix_json(mh.ENTERPRISE_ATTACK)
    tfu.save_to_json_file(strix_json, mh.ENTERPRISE_ATTACK)


def get_enterprise_groups():
    """
    Metodo per ottenere i gruppi (attaccanti) enterprise del modello ATT&CK
    :return: lista di stix2.v20.sdo.IntrusionSet
    """
    groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)
    print(groups[0].serialize(indent=4))
    return groups


def get_enterprise_mitigations():
    """
    Metodo per ottenere le mitigazioni enterprise del modello ATT&CK
    :return: lista di stix2.v20.sdo.CourseOfAction
    """
    mitigations = mitre_attack_data.get_mitigations(remove_revoked_deprecated=True)
    return mitigations


def get_enterprise_attack_id_from_intrusionset_id(intrusionset_id):
    """
    Restituisce l'id del gruppo dato un intrusion_set id
    :param intrusionset_id: id
    :return: id del gruppo
    """
    attack_id = mitre_attack_data.get_attack_id(intrusionset_id)
    return attack_id


def get_enterprise_software():
    """
    Metodo per ottenere una lista di software utilizzati in ambito enterprise.<br/>
    Questi software possono essere sia tool che malware.
    :return: Lista di stix2.v20.sdo.Tool e stix2.v20.sdo.Malware
    """
    software = mitre_attack_data.get_software(remove_revoked_deprecated=True)
    return software


def get_obj_name_from_stix_id(stix_id):
    """
    Metodo per ottenere, dato uno stix_id, il nome dell'oggetto definito dall'id.
    Ad esempio, dato un intrusionset_id, restituisce il nome del gruppo
    :param stix_id: id da analizzare
    :return: nome dell'oggetto
    """
    object_name = mitre_attack_data.get_name(stix_id)
    return object_name


def get_enterprise_campaigns():
    """
    Metodo per ottenere una lista di campagne, che descrivono un gruppo di attività intrusive
    avvenute lungo un periodo di tempo specifico, con target ed obiettivi comuni
    :return: Lista di stix2.v20.sdo.Campaign
    """
    campaigns = mitre_attack_data.get_campaigns(remove_revoked_deprecated=True)
    print(type(campaigns[0]))
    return campaigns


def get_all_campaigns_attributed_to_group(group_name: str = None, group_id: str = None):
    """
    Metodo che permette, dato un nome_gruppo o id_gruppo (sono mutuamente esclusivi), di ricavare tutte le campagne
    attribuite a tale gruppo
    :param group_name: nome gruppo
    :param group_id: id gruppo
    :return: lista di Campaign
    """
    if not group_name and not group_id:
        raise TypeError("La chiamata ha bisogno di un group_name o group_id")
    elif group_name and group_id:
        raise TypeError("La chiamata non può essre eseguita con group_name e gourp_id. Indicarne solo uno")

    group = None
    if group_id:
        group = get_obj_name_from_stix_id(group_id)
    else:
        group = group_name

    # get all campaigns related to group
    campaigns_attributed = mitre_attack_data.get_all_campaigns_attributed_to_all_groups()
    res = []
    for identifier, campaigns in campaigns_attributed.items():
        if get_obj_name_from_stix_id(identifier).lower() == group.lower():
            for elem in campaigns:
                res.append(elem['object'])

    return res


def main():
    # get all campaigns related to groups
    campaigns_attributed = mitre_attack_data.get_all_campaigns_attributed_to_all_groups()
    print(f"Campaigns attributed to groups ({len(campaigns_attributed.keys())} groups):")
    for id, campaigns in campaigns_attributed.items():
        print(f"* {id} - attributing to {len(campaigns)} {'campaign' if len(campaigns) == 1 else 'campaigns'}")
