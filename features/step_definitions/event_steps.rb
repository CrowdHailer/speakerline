Given(/^I am on the 'Add an Event' page$/) do
  visit new_event_instance_path
end

Given('there is not an event called {string}') do |event_name|
  event.destroy if event = Event.find_by(name: event_name)
end

When('I am on the {string} event page') do |event_name|
  event = Event.find_by(name: event_name)
  visit event_path(event)
end

Then('I should see a link to the main {string} event page') do |event_name|
  event = Event.find_by(name: event_name)
  expect(page).to  have_link(event.name, href: event_path(event))
end
