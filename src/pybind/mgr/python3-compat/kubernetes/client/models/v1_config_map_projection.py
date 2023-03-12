# coding: utf-8

"""
    Kubernetes

    No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)  # noqa: E501

    The version of the OpenAPI document: release-1.25
    Generated by: https://openapi-generator.tech
"""


import pprint
import re  # noqa: F401

import six

from kubernetes.client.configuration import Configuration


class V1ConfigMapProjection(object):
    """NOTE: This class is auto generated by OpenAPI Generator.
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """

    """
    Attributes:
      openapi_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    openapi_types = {
        'items': 'list[V1KeyToPath]',
        'name': 'str',
        'optional': 'bool'
    }

    attribute_map = {
        'items': 'items',
        'name': 'name',
        'optional': 'optional'
    }

    def __init__(self, items=None, name=None, optional=None, local_vars_configuration=None):  # noqa: E501
        """V1ConfigMapProjection - a model defined in OpenAPI"""  # noqa: E501
        if local_vars_configuration is None:
            local_vars_configuration = Configuration()
        self.local_vars_configuration = local_vars_configuration

        self._items = None
        self._name = None
        self._optional = None
        self.discriminator = None

        if items is not None:
            self.items = items
        if name is not None:
            self.name = name
        if optional is not None:
            self.optional = optional

    @property
    def items(self):
        """Gets the items of this V1ConfigMapProjection.  # noqa: E501

        items if unspecified, each key-value pair in the Data field of the referenced ConfigMap will be projected into the volume as a file whose name is the key and content is the value. If specified, the listed keys will be projected into the specified paths, and unlisted keys will not be present. If a key is specified which is not present in the ConfigMap, the volume setup will error unless it is marked optional. Paths must be relative and may not contain the '..' path or start with '..'.  # noqa: E501

        :return: The items of this V1ConfigMapProjection.  # noqa: E501
        :rtype: list[V1KeyToPath]
        """
        return self._items

    @items.setter
    def items(self, items):
        """Sets the items of this V1ConfigMapProjection.

        items if unspecified, each key-value pair in the Data field of the referenced ConfigMap will be projected into the volume as a file whose name is the key and content is the value. If specified, the listed keys will be projected into the specified paths, and unlisted keys will not be present. If a key is specified which is not present in the ConfigMap, the volume setup will error unless it is marked optional. Paths must be relative and may not contain the '..' path or start with '..'.  # noqa: E501

        :param items: The items of this V1ConfigMapProjection.  # noqa: E501
        :type: list[V1KeyToPath]
        """

        self._items = items

    @property
    def name(self):
        """Gets the name of this V1ConfigMapProjection.  # noqa: E501

        Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names  # noqa: E501

        :return: The name of this V1ConfigMapProjection.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this V1ConfigMapProjection.

        Name of the referent. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names  # noqa: E501

        :param name: The name of this V1ConfigMapProjection.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def optional(self):
        """Gets the optional of this V1ConfigMapProjection.  # noqa: E501

        optional specify whether the ConfigMap or its keys must be defined  # noqa: E501

        :return: The optional of this V1ConfigMapProjection.  # noqa: E501
        :rtype: bool
        """
        return self._optional

    @optional.setter
    def optional(self, optional):
        """Sets the optional of this V1ConfigMapProjection.

        optional specify whether the ConfigMap or its keys must be defined  # noqa: E501

        :param optional: The optional of this V1ConfigMapProjection.  # noqa: E501
        :type: bool
        """

        self._optional = optional

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.openapi_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, V1ConfigMapProjection):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, V1ConfigMapProjection):
            return True

        return self.to_dict() != other.to_dict()
