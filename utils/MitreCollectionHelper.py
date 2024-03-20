import requests
import re
from stix2 import TAXIICollectionSource, MemoryStore, parse
from taxii2client.v20 import Collection, Server  # only specify v20 if your installed version is >= 2.0.0


ENTERPRISE_ATTACK = 'enterprise-attack'
MOBILE_ATTACK = 'mobile-attack'
ICS_ATTACK = 'ics-attack'


collections = {
    ENTERPRISE_ATTACK: "95ecc380-afe9-11e4-9b6c-751b66dd541e",
    MOBILE_ATTACK: "2f669986-b40b-4423-b720-4396ca6a462b",
    ICS_ATTACK: "02c3ef24-9cd4-48f3-a99f-b74ce24f1d34"
}


def retreive_collections(url: str = "https://cti-taxii.mitre.org/taxii/"):
    """
    Metodo che permette, dato un server, di ottenere le collezioni disponibili.
    :param url: URL del server da interrogare (default server TAXII)
    :return: lista di Collection
    """
    server = Server(url)
    api_root = server.api_roots[0]
    return api_root.collections


def get_collection(collection_name: str):
    """
    Metodo che permette di ottenere una collezione dato un nome.<br/>
    :param collection_name: può essere 'enterprise-attack' | 'mobile-attack' | 'ics-attack'
    :return: TAXIICollectionSource
    """
    if collection_name not in collections:
        raise ValueError("Dominio inserito non valido")
    collection = Collection(f"https://cti-taxii.mitre.org/stix/collections/{collections[collection_name]}/")
    src = TAXIICollectionSource(collection)
    return src


def get_stix_json(domain: str, branch: str = "master"):
    """
        Metodo che permette di ottenere i dati dell'ATT&CK STIX dal MITRE/CTI mediante request.
        :param domain: può essere 'enterprise-attack' | 'mobile-attack' | 'ics-attack'
        :param branch: tipicamente 'master'
        :return: JSON
        """
    if domain not in collections:
        raise ValueError("Dominio inserito non valido")
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre/cti/{branch}/{domain}/{domain}.json").json()
    return stix_json


def get_data_from_branch(domain: str, branch: str = "master"):
    """
    Metodo che permette di ottenere i dati dell'ATT&CK STIX dal MITRE/CTI mediante request.
    :param domain: può essere 'enterprise-attack' | 'mobile-attack' | 'ics-attack'
    :param branch: tipicamente 'master'
    :return: MemoryStore
    """
    return MemoryStore(stix_data=get_stix_json(domain, branch)["objects"])


def get_attack_versions():
    """
    Metodo che permette di ottenere una lista delle versioni di ATT&CK.
    :return: lista di str (versions = ["1.0", "2.0", ...])
    """
    refToTag = re.compile(r"ATT&CK-v(.*)")
    tags = requests.get("https://api.github.com/repos/mitre/cti/git/refs/tags").json()
    versions = list(
        map(lambda tag: refToTag.search(tag["ref"]).groups()[0], filter(lambda tag: "ATT&CK-v" in tag["ref"], tags)))
    return versions


def get_data_from_version(domain: str, version: str):
    """
    Metodo che permette di ottenere i dati di una specifica versione dell'ATT&CK per
    un determinato dominio.
    :param domain: può essere 'enterprise-attack' | 'mobile-attack' | 'ics-attack'
    :param version: versione
    :return: MemoryStore
    """
    if domain not in collections:
        raise ValueError("Dominio inserito non valido")
    stix_json = requests.get(
        f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{version}/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])
