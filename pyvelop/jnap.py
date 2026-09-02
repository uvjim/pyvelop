"""Interact with the JNAP API."""

# region #-- imports --#
from __future__ import annotations

import base64
import copy
import json
import logging
import re
from typing import Any, TypeGuard, cast

import aiohttp

from .action_registry import ActionDefinition, Actions
from .exceptions import (
    MeshActionUnknown,
    MeshAlreadyInProgress,
    MeshCannotDeleteDevice,
    MeshConnectionError,
    MeshDeviceDbFailure,
    MeshException,
    MeshInvalidCredentials,
    MeshInvalidCredentialsWithDelay,
    MeshInvalidInput,
    MeshInvalidOutput,
    MeshNodeNotPrimary,
    MeshTimeoutError,
)
from .logger import Logger

# endregion

_LOGGER: Logger = Logger(logging.getLogger(__name__))
_LOGGER_VERBOSE = Logger(logging.getLogger(f"{__name__}.verbose"))


type JnapResponseSingle = dict[str, Any]
type JnapResponseTransaction = dict[str, list[JnapResponseSingle]]
type JnapPayloadSingle = dict[str, Any]
type JnapPayloadTransaction = list[JnapPayloadSingle]


def _is_transaction_response(
    payload: JnapResponseSingle | JnapResponseTransaction,
) -> TypeGuard[JnapResponseTransaction]:
    """Return True if the payload represents a transaction response."""
    return isinstance(payload, dict) and isinstance(payload.get("responses"), list)


def _iter_response_entries(response: dict[str, Any]) -> list[tuple[int, JnapResponseSingle]]:
    """Yield (index, response entry) for a single or transaction response."""
    if _is_transaction_response(response):
        return list(enumerate(response["responses"]))
    return [(0, response)]


def as_items(payload: JnapResponseSingle | JnapResponseTransaction) -> list[JnapResponseSingle]:
    """Return the promoted output entries for either a single or transaction response."""
    if _is_transaction_response(payload):
        return [item.get("output", item) for item in payload["responses"] if isinstance(item, dict)]

    if isinstance(payload, dict):
        return [cast(JnapResponseSingle, payload.get("output", payload))]

    return list[JnapResponseSingle]()


def jnap_url(target: str) -> str:
    """Return the URL that should be used for the request.

    :param target: the API host
    :return: string containing the base URL for all JNAP requests
    """
    return f"http://{target}/JNAP/"


class Request:
    """Represents a request for the API."""

    def __init__(
        self,
        action: str,
        password: str,
        target: str,
        payload: JnapPayloadSingle | JnapPayloadTransaction | None = None,
        raise_on_error: bool = True,
        session: aiohttp.ClientSession | None = None,
        username: str = "admin",
        redact: bool = True,
        supplementary_redactions: dict[str, set[str]] | None = None,
    ) -> None:
        """Initialise a request.

        :param action: the JNAP action to carry out
        :param password: the password required to communicate with the target
        :param target: the node to send the request to
        :param payload: the additional configuration to pass along with the action
        :param raise_on_error: raise an error if one is found
        :param session: an existing session to use
        :param username: the username required to communicate with the target
        :param redact: `True` to enable redaction
        :param supplementary_redactions: additional redactions to be applied to the logging
        """
        self._action: str = action
        self._creds: str = base64.b64encode(bytes(f"{username}:{password}", "utf-8")).decode("ascii")
        self._payload: JnapPayloadSingle | JnapPayloadTransaction = payload if payload is not None else {}
        self._raise_on_error: bool = raise_on_error
        self._redact: bool = redact
        self._session: aiohttp.ClientSession = (
            session if session is not None else aiohttp.ClientSession(raise_for_status=True)
        )
        self._supplementary_redactions: dict[str, set[str]] = supplementary_redactions or {}

        self._jnap_url: str = jnap_url(target=target)

    def _get_action_key_from_uri(self, action_uri: str) -> str:
        """Get the ActionKey from an action URI.

        :param action_uri: the action URI to look up
        :return: the ActionKey if found, otherwise the original URI string
        """
        # Try to match by action_base (with or without version suffix)
        for action_def in Actions.values():
            # Check exact match or version-suffixed match
            if action_uri == action_def.action_base or action_uri.startswith(action_def.action_base):
                return action_def.key
        return action_uri

    def _build_redactions(self, key: str) -> set[str]:
        """Build the set of redactions for a given action key.

        :param key: the action key to look up redactions for
        :return: the set of field names to redact
        """
        ret: set[str] = set()
        action: ActionDefinition | None = next((a for a in Actions.values() if a.key == key), None)

        if action is not None:
            ret = action.redactions.union(self._supplementary_redactions.get(action.key, set()))

        return ret

    def _redact_payload(
        self,
        payload: JnapPayloadSingle | JnapPayloadTransaction,
        action_uri: str,
    ) -> JnapPayloadSingle | JnapPayloadTransaction:
        """Redact sensitive data from request payload.

        :param payload: the payload to redact
        :param action_uri: the action URI for redaction lookup
        :return: redacted copy of the payload
        """
        action_key = self._get_action_key_from_uri(action_uri)
        redactions = self._build_redactions(action_key)
        if not redactions:
            return payload

        if isinstance(payload, list):
            # Transaction: redact each payload entry
            return [_LOGGER.redact(p, redactions) if isinstance(p, dict) else p for p in payload]

        if isinstance(payload, dict):
            # Single: redact the payload dict
            return _LOGGER.redact(payload, redactions)

        return payload

    def _redact_response(
        self,
        response: JnapResponseSingle | JnapResponseTransaction,
    ) -> JnapResponseSingle | JnapResponseTransaction:
        """Redact sensitive data from response.

        :param response: the response to redact
        :return: redacted copy of the response
        """
        # Only redact successful responses
        if response.get("result") != "OK":
            return response

        redacted = copy.deepcopy(response)

        if _is_transaction_response(redacted):
            # Transaction: redact each response entry
            for idx, r_entry in enumerate(redacted.get("responses", [])):
                if isinstance(r_entry, dict) and r_entry.get("result") == "OK":
                    # Use action from payload[idx] or fallback to the main action
                    action_uri = self._action
                    if isinstance(self._payload, list) and idx < len(self._payload):
                        action_uri = self._payload[idx].get("action", self._action)

                    # Convert URI to ActionKey for redaction lookup
                    action_key = self._get_action_key_from_uri(action_uri)
                    redactions = self._build_redactions(action_key)
                    if redactions:
                        r_entry["output"] = _LOGGER.redact(r_entry.get("output", {}), redactions)
            return redacted

        # Single response: redact the output
        action_key = self._get_action_key_from_uri(self._action)
        redactions = self._build_redactions(action_key)
        if redactions:
            redacted_single = cast(JnapResponseSingle, redacted)
            output = redacted_single.get("output", {})
            if isinstance(output, dict):
                redacted_single["output"] = _LOGGER.redact(output, redactions)
        return redacted

    async def execute(self, timeout: float = 10) -> Response:
        """Send the request.

        :param timeout: the timeout in seconds for the request, defaults to 10s
        :return: a Response object representing the returned results
        """

        headers: dict[str, str] = {
            "Accept": "*/*",
            "Content-Type": "application/json",
            "X-JNAP-Action": self._action,
            "X-JNAP-Authorization": f"Basic {self._creds}",
        }

        resp: aiohttp.ClientResponse | None = None
        try:
            resp = await self._session.post(
                url=self._jnap_url,
                headers=headers,
                json=self._payload,
                timeout=timeout,  # pyright:ignore[reportArgumentType] if float is passed it's classed as total
            )
            resp_json: dict[str, Any] = await resp.json()
        except TimeoutError as err:
            raise MeshTimeoutError from err
        except (
            aiohttp.ClientConnectionError,
            aiohttp.ClientConnectorError,
            aiohttp.ContentTypeError,
        ) as err:
            raise MeshConnectionError from err

        # region #-- log the response --#
        to_log: dict[str, Any] = {
            "action": self._action,
            "payload": self._redact_payload(self._payload, self._action) if self._redact else self._payload,
            "response": self._redact_response(resp_json) if self._redact else copy.deepcopy(resp_json),
        }
        _LOGGER_VERBOSE.debug(json.dumps(to_log))
        # endregion

        ret = Response(action=self.action, data=resp_json, raise_on_error=self._raise_on_error)

        return ret

    @property
    def action(self) -> str:
        """Return the action used in the request.

        :return: string containing the action
        """
        return self._action

    @property
    def payload(self) -> JnapPayloadSingle | JnapPayloadTransaction:
        """Return the payload used for the request.

        :return: the payload
        """
        return self._payload


class Response:
    """Represents a response from the API."""

    DATA_KEY_SINGLE: str = "output"
    DATA_KEY_TRANSACTION: str = "responses"
    RESULT_KEY: str = "result"

    def __init__(self, action: str, data: dict[str, Any], raise_on_error: bool = True) -> None:
        """Initialise the response.

        :param action: The action that was issued in the request to cause the response
        :param data: The JSON response received in response to the API call
        :param raise_on_error: `True` to raise an exception if an error was found in he repsonse
        """
        self._action: str = action
        self._data: dict[str, Any] = data
        self._raise_on_error: bool = raise_on_error

        self._process_data()

    def _process_data(self) -> None:
        """Process the given data to check for errors."""

        if self._data is None:
            return

        err: MeshException | None = None

        if self._data.get(self.RESULT_KEY) != "OK":  # seemingly there is an error
            # build a list of the responses - transactions will already be a list
            responses = (
                self._data.get(self.DATA_KEY_TRANSACTION, []) if _is_transaction_response(self._data) else [self._data]
            )

            # establish errors and work through them
            err_responses = [resp for resp in responses if resp.get(self.RESULT_KEY) != "OK"]
            for resp in err_responses:  # loop through the responses
                err = None
                if resp is None:
                    err = MeshInvalidOutput()
                elif resp.get(self.RESULT_KEY) == "_ErrorInvalidInput":
                    err = MeshInvalidInput(resp.get("error"))
                elif resp.get(self.RESULT_KEY) == "_ErrorInvalidOutput":
                    err = MeshInvalidOutput(resp.get("error"))
                elif resp.get(self.RESULT_KEY) == "_ErrorUnauthorized":
                    err_details = resp.get("error")
                    err = MeshInvalidCredentials(details=err_details)
                elif resp.get(self.RESULT_KEY) == "_ErrorUnknownAction":
                    action: str = ""
                    if "error" in resp:
                        match = re.search(r"'(https?://[^']+)'", resp.get("error", ""))
                        uri = match.group(1) if match else ""
                        action = uri
                    else:
                        action = self.action
                    err = MeshActionUnknown(action)
                elif resp.get(self.RESULT_KEY) == "ErrorAutoChannelSelectionAlreadyInProgress":
                    err = MeshAlreadyInProgress()
                elif resp.get(self.RESULT_KEY) == "ErrorCannotDeleteDevice":
                    err = MeshCannotDeleteDevice()
                elif resp.get(self.RESULT_KEY) == "ErrorDeviceDBFailure":
                    err = MeshDeviceDbFailure(resp.get(self.DATA_KEY_SINGLE, {}).get("ErrorInfo", ""))
                elif resp.get(self.RESULT_KEY) == "ErrorDeviceNotInMasterMode":
                    err = MeshNodeNotPrimary()
                elif resp.get(self.RESULT_KEY) == "ErrorInvalidAdminPassword":
                    err_details = resp.get(self.DATA_KEY_SINGLE, {})
                    err = MeshInvalidCredentialsWithDelay(
                        details={
                            "attempts_remaining": err_details.get("attemptsRemaining"),
                            "delay_time_remaining_secs": err_details.get("delayTimeRemaining"),
                        }
                    )
                elif resp.get(self.RESULT_KEY) == "ErrorInvalidWANSchedule":
                    err = MeshInvalidInput("Invalid WAN Schedule")
                elif resp.get(self.RESULT_KEY) == "ErrorRulesOverlap":
                    err = MeshInvalidInput("Rules Overlap")
                elif resp.get(self.RESULT_KEY) == "ErrorUnknownDevice":
                    err = MeshInvalidInput("Unknown Device")
                elif resp.get(self.RESULT_KEY, "").startswith("_"):
                    err = MeshInvalidInput(f"{resp.get(self.RESULT_KEY)}: '{self.action}'")
                else:  # don't know the error, log and raise exception
                    _LOGGER.error("unknown error received: %s", self._data)
                    err = MeshException(json.dumps(resp.get(self.RESULT_KEY)))
                if err:  # break out of the for loop if we have an error
                    break

        if err and self._raise_on_error:
            raise err

    @property
    def action(self) -> str:
        """Return the action that resulted in the response.

        :return: string containing the action
        """
        return self._action

    @property
    def data(self) -> list[dict[str, Any]]:
        """Compatibility property: always list-like."""
        return self.items

    @property
    def items(self) -> list[JnapResponseSingle]:
        """Return the response entries in list form."""
        return as_items(self._data)
